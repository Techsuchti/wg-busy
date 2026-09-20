package network

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/yix/wg-busy/internal/models"
)

const (
	pingTimeout = 1200 * time.Millisecond
	maxScanHosts = 1024
)

// ScanPeer discovers IPv4 hosts behind a WireGuard peer. If explicitCIDR is
// supplied it is used first. Otherwise the scanner uses AdvertisedRoutes and,
// as a fallback, non-host IPv4 AllowedIPs configured for the peer. This means
// a normal routed peer can be scanned without duplicating its network in a
// second UI field, while an explicit CIDR is still available for unusual setups.
func ScanPeer(peer models.Peer, explicitCIDR string) ([]models.PeerNetworkDevice, error) {
	var rawNetworks []string
	if strings.TrimSpace(explicitCIDR) != "" {
		rawNetworks = strings.FieldsFunc(explicitCIDR, func(r rune) bool { return r == ',' || r == ';' || r == '\\n' || r == '\\r' || r == ' ' || r == '\\t' })
	} else {
		rawNetworks = append(rawNetworks, peer.AdvertisedRoutes...)
		if len(rawNetworks) == 0 {
			rawNetworks = append(rawNetworks, peer.AllowedIPs...)
		}
	}

	var networks []*net.IPNet
	for _, raw := range rawNetworks {
		_, network, err := net.ParseCIDR(strings.TrimSpace(raw))
		if err != nil {
			continue
		}
		if network.IP.To4() == nil {
			continue
		}
		network.IP = network.IP.To4()
		networks = append(networks, network)
	}

	if len(networks) == 0 {
		return nil, fmt.Errorf("keine gültigen IPv4-Netze gefunden. Trage unter „Angekündigte Routen“ ein LAN-Netz ein oder gib beim Scan ein CIDR an, z. B. 192.168.178.0/24")
	}

	var hosts []net.IP
	for _, network := range networks {
		ones, bits := network.Mask.Size()
		if bits != 32 || ones > 30 {
			continue
		}
		count := 1 << uint(bits-ones)
		if count > maxScanHosts {
			return nil, fmt.Errorf("Netz %s ist zu groß für einen Scan (maximal %d Hosts)", network.String(), maxScanHosts)
		}
		base := uint32(network.IP[0])<<24 | uint32(network.IP[1])<<16 | uint32(network.IP[2])<<8 | uint32(network.IP[3])
		for i := 1; i < count-1; i++ {
			v := base + uint32(i)
			ip := net.IPv4(byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
			hosts = append(hosts, ip)
		}
	}

	seen := make(map[string]bool)
	unique := hosts[:0]
	for _, ip := range hosts {
		key := ip.String()
		if !seen[key] {
			seen[key] = true
			unique = append(unique, ip)
		}
	}
	hosts = unique

	var wg sync.WaitGroup
	results := make(chan models.PeerNetworkDevice, len(hosts))
	sem := make(chan struct{}, 32)

	for _, ip := range hosts {
		ip := ip
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			ctx, cancel := context.WithTimeout(context.Background(), pingTimeout)
			defer cancel()
			cmd := exec.CommandContext(ctx, "ping", "-4", "-c", "1", "-W", "1", ip.String())
			if err := cmd.Run(); err != nil {
				return
			}

			hostname := ""
			if names, err := net.LookupAddr(ip.String()); err == nil && len(names) > 0 {
				hostname = strings.TrimSuffix(names[0], ".")
			}

			results <- models.PeerNetworkDevice{
				IP:       ip.String(),
				Hostname: hostname,
				Online:   true,
				LastSeen: time.Now().UTC(),
			}
		}()
	}

	wg.Wait()
	close(results)

	devices := make([]models.PeerNetworkDevice, 0, len(results))
	for device := range results {
		devices = append(devices, device)
	}
	sort.Slice(devices, func(i, j int) bool {
		return ipLess(devices[i].IP, devices[j].IP)
	})
	return devices, nil
}

func ipLess(a, b string) bool {
	ia := net.ParseIP(a).To4()
	ib := net.ParseIP(b).To4()
	if ia == nil || ib == nil {
		return a < b
	}
	for i := 0; i < 4; i++ {
		if ia[i] != ib[i] {
			return ia[i] < ib[i]
		}
	}
	return false
}
