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
	pingTimeout  = 1200 * time.Millisecond
	maxScanHosts = 1024
)

// ScanPeer discovers IPv4 hosts behind a WireGuard peer.
//
// Priority:
//  1. An explicitly supplied CIDR.
//  2. Advertised routes configured for the peer.
//  3. IPv4 routes currently installed on the Linux host via wg0 that are not
//     just the peer's own /32 or /128 address.
//  4. IPv4 AllowedIPs, excluding host routes (/32).
//
// A WireGuard peer address such as 10.66.0.2/32 does not describe the LAN
// behind the peer, so it is deliberately not treated as a scan network.
func ScanPeer(peer models.Peer, explicitCIDR string) ([]models.PeerNetworkDevice, error) {
	var rawNetworks []string

	if strings.TrimSpace(explicitCIDR) != "" {
		rawNetworks = splitNetworks(explicitCIDR)
	} else {
		rawNetworks = append(rawNetworks, peer.AdvertisedRoutes...)
	}

	rawNetworks = append(rawNetworks, linuxWGNetworks(peer)...)

	if len(rawNetworks) == 0 {
		rawNetworks = append(rawNetworks, nonHostIPv4Networks(peer.AllowedIPs)...)
	}

	networks := parseIPv4Networks(rawNetworks)
	if len(networks) == 0 {
		return nil, fmt.Errorf(
			"Für diesen Peer wurde kein geroutetes IPv4-LAN gefunden. Der Peer selbst (%s) ist nur eine Host-Adresse. Gib beim Scan ein LAN-CIDR an, z. B. 192.168.178.0/24, oder kündige das LAN-Netz über diesen Peer an.",
			peerAddressSummary(peer),
		)
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

		base := uint32(network.IP[0])<<24 |
			uint32(network.IP[1])<<16 |
			uint32(network.IP[2])<<8 |
			uint32(network.IP[3])

		for i := 1; i < count-1; i++ {
			v := base + uint32(i)
			hosts = append(hosts, net.IPv4(byte(v>>24), byte(v>>16), byte(v>>8), byte(v)))
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

			host := ""
			if names, err := net.LookupAddr(ip.String()); err == nil && len(names) > 0 {
				host = strings.TrimSuffix(names[0], ".")
			}

			results <- models.PeerNetworkDevice{
				IP:       ip.String(),
				Hostname: host,
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

// linuxWGNetworks returns IPv4 routes currently known to Linux through wg0.
// This catches routed LANs that were installed dynamically and are not present
// in the peer's AdvertisedRoutes field.
func linuxWGNetworks(peer models.Peer) []string {
	out, err := exec.Command("ip", "-4", "route", "show", "table", "all", "dev", models.WGDevice).Output()
	if err != nil {
		return nil
	}

	peerIPs := make(map[string]bool)
	for _, source := range models.PeerSources(peer.AllowedIPs) {
		ip, network, err := net.ParseCIDR(source)
		if err != nil || ip.To4() == nil {
			continue
		}
		if ones, bits := network.Mask.Size(); bits == 32 && ones == 32 {
			peerIPs[ip.To4().String()] = true
		}
	}

	var networks []string
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}

		// Examples:
		//   192.168.178.0/24 scope link
		//   192.168.178.0/24 via 10.66.0.2 dev wg0
		//   10.66.0.2 dev wg0 scope link
		candidate := fields[0]
		if candidate == "default" || !strings.Contains(candidate, "/") {
			continue
		}

		ip, network, err := net.ParseCIDR(candidate)
		if err != nil || ip.To4() == nil {
			continue
		}

		ones, bits := network.Mask.Size()
		if bits != 32 {
			continue
		}

		// Do not scan the WireGuard peer's tunnel address as if it were a LAN.
		if ones == 32 && peerIPs[ip.To4().String()] {
			continue
		}

		// Avoid scanning tiny host routes that are not useful as a LAN.
		if ones > 30 {
			continue
		}

		networks = append(networks, network.String())
	}

	return uniqueStrings(networks)
}

func nonHostIPv4Networks(value string) []string {
	var result []string
	for _, raw := range splitNetworks(value) {
		ip, network, err := net.ParseCIDR(strings.TrimSpace(raw))
		if err != nil || ip.To4() == nil {
			continue
		}
		ones, bits := network.Mask.Size()
		if bits == 32 && ones < 32 {
			result = append(result, network.String())
		}
	}
	return uniqueStrings(result)
}

func parseIPv4Networks(rawNetworks []string) []*net.IPNet {
	var networks []*net.IPNet
	seen := make(map[string]bool)

	for _, raw := range rawNetworks {
		_, network, err := net.ParseCIDR(strings.TrimSpace(raw))
		if err != nil || network.IP.To4() == nil {
			continue
		}

		network.IP = network.IP.To4()
		ones, bits := network.Mask.Size()
		if bits != 32 || ones > 30 {
			continue
		}

		key := network.String()
		if seen[key] {
			continue
		}
		seen[key] = true
		networks = append(networks, network)
	}

	return networks
}

func splitNetworks(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == ';' || r == '\n' || r == '\r' || r == ' ' || r == '\t'
	})
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]bool)
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		result = append(result, value)
	}
	return result
}

func peerAddressSummary(peer models.Peer) string {
	var addresses []string
	for _, source := range models.PeerSources(peer.AllowedIPs) {
		if strings.Contains(source, ":") {
			continue
		}
		addresses = append(addresses, source)
	}
	if len(addresses) == 0 {
		return "unbekannt"
	}
	return strings.Join(addresses, ", ")
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
