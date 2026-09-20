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

// ScanPeer discovers IPv4 hosts on networks advertised by the selected peer.
// It deliberately scans only the peer's configured AdvertisedRoutes; it never
// probes arbitrary networks. This makes the feature useful for routers/LANs
// behind a WireGuard peer while keeping the scan scope explicit.
func ScanPeer(peer models.Peer) ([]models.PeerNetworkDevice, error) {
	var networks []*net.IPNet
	for _, raw := range peer.AdvertisedRoutes {
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
		return nil, fmt.Errorf("der Peer hat keine gültigen IPv4-Netze unter „Advertised Routes“ eingetragen")
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
		for i := 1; i < count-1; i++ {
			ip := append(net.IP(nil), network.IP...)
			for j := 3; j >= 0; j-- {
				ip[j] += byte(i >> uint(8*(3-j)))
			}
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
