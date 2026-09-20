package routing

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"sort"
	"strings"

	"github.com/yix/wg-busy/internal/models"
)

var (
	interfaceUp = func() bool {
		_, err := exec.Command("ip", "link", "show", models.WGDevice).Output()
		return err == nil
	}
	runShellCommand = func(command string) ([]byte, error) {
		return exec.Command("sh", "-c", command).CombinedOutput()
	}
)

const routingTableBase uint = 100

// AssignRoutingTableID finds the next unused routing table ID for an exit node.
func AssignRoutingTableID(peers []models.Peer) uint {
	used := make(map[uint]bool)
	for _, p := range peers {
		if p.RoutingTableID > 0 {
			used[p.RoutingTableID] = true
		}
		if p.PolicyRoutingTableID > 0 {
			used[p.PolicyRoutingTableID] = true
		}
	}
	for id := routingTableBase; ; id++ {
		if !used[id] {
			return id
		}
	}
}

// rulePriorityBase is where generated `ip rule` priorities start. Priorities are
// explicit because `ip rule add` without one assigns a *descending* number, so
// the last rule added would be evaluated first — which would put a strict peer's
// reject rule ahead of its own table lookup and blackhole everything.
// The range stays well below main (32766) so these rules are consulted first.
const rulePriorityBase = 10000

// peerRule is one `ip rule` entry. Both PostUp and PostDown render from the same
// specs, so teardown always matches what was installed.
type peerRule struct {
	IPCommand string // "ip" for IPv4, "ip -6" for IPv6
	Selector  string // e.g. "from 10.0.0.5"
	Action    string // e.g. "table 100" or "prohibit"
	Priority  int
}

// peerRules returns every ip rule to install, in evaluation order.
//
// A peer's own lookups come first, and a strict peer gets a trailing reject so
// unmatched traffic stops there instead of falling through to the main table.
func peerRules(cfg models.AppConfig, exitNodes map[string]models.Peer) []peerRule {
	var rules []peerRule
	prio := rulePriorityBase

	for _, p := range cfg.Peers {
		if !p.Enabled {
			continue
		}
		peerSources := models.PeerSources(p.AllowedIPs)
		if len(peerSources) == 0 {
			continue
		}
		for _, peerSource := range peerSources {
			ipCommand := "ip"
			if strings.Contains(peerSource, ":") {
				ipCommand = "ip -6"
			}
			selector := "from " + peerSource

			// Exit node table, when this peer routes through one.
			if p.ExitNodeID != "" {
				if exitNode, ok := exitNodes[p.ExitNodeID]; ok {
					rules = append(rules, peerRule{ipCommand, selector, fmt.Sprintf("table %d", exitNode.RoutingTableID), prio})
					prio++
				}
			}

			// The peer's own policy table.
			if len(p.PolicyRoutes) > 0 && p.PolicyRoutingTableID > 0 {
				rules = append(rules, peerRule{ipCommand, selector, fmt.Sprintf("table %d", p.PolicyRoutingTableID), prio})
				prio++
			}

			// Strict always fails closed. Validation normally guarantees a lookup
			// first, but a hand-edited invalid config must never fall through to main.
			if p.StrictPolicyRouting {
				rules = append(rules, peerRule{ipCommand, selector, "prohibit", prio})
				prio++
			}
		}
	}
	return rules
}

const (
	strictChainV4       = "WG_BUSY_STRICT4"
	strictChainV6       = "WG_BUSY_STRICT6"
	strictApplyComment  = "wg-busy strict apply"
)

// strictEgressRule represents one firewall rule in WG_BUSY_STRICT4 or WG_BUSY_STRICT6.
type strictEgressRule struct {
	IsV6   bool
	Source string
	Dest   string // empty for terminal reject
	OutDev string // empty for terminal reject
	Action string // "RETURN" or "REJECT"
}

// strictEgressRules returns all allow-return and terminal reject rules for strict peers.
func strictEgressRules(cfg models.AppConfig, gateways []models.GatewayNet, exitNodes map[string]models.Peer) []strictEgressRule {
	var rules []strictEgressRule

	for _, p := range cfg.Peers {
		if !p.Enabled || !p.StrictPolicyRouting {
			continue
		}
		sources := models.PeerSources(p.AllowedIPs)
		if len(sources) == 0 {
			continue
		}

		for _, src := range sources {
			isV6 := strings.Contains(src, ":")

			// 1. Exit node routes for strict peer
			if p.ExitNodeID != "" {
				if exitNode, ok := exitNodes[p.ExitNodeID]; ok {
					if exitNode.ExitNodeAllowAll {
						if !isV6 {
							rules = append(rules, strictEgressRule{IsV6: false, Source: src, Dest: "0.0.0.0/0", OutDev: models.WGDevice, Action: "RETURN"})
						} else {
							rules = append(rules, strictEgressRule{IsV6: true, Source: src, Dest: "::/0", OutDev: models.WGDevice, Action: "RETURN"})
						}
					} else {
						for _, r := range exitNode.ExitNodeRoutes {
							r = strings.TrimSpace(r)
							if r == "" {
								continue
							}
							ip, _, err := net.ParseCIDR(r)
							if err != nil {
								continue
							}
							routeIsV6 := ip.To4() == nil
							if routeIsV6 == isV6 {
								rules = append(rules, strictEgressRule{IsV6: isV6, Source: src, Dest: r, OutDev: models.WGDevice, Action: "RETURN"})
							}
						}
					}
				}
			}

			// 2. Policy routes for strict peer
			for _, routeStr := range p.PolicyRoutes {
				parts := strings.Split(routeStr, " via ")
				if len(parts) != 2 {
					continue
				}
				subnet := strings.TrimSpace(parts[0])
				gw := strings.TrimSpace(parts[1])

				ip, _, err := net.ParseCIDR(subnet)
				if err != nil {
					continue
				}
				routeIsV6 := ip.To4() == nil
				if routeIsV6 != isV6 {
					continue
				}

				dev, err := models.ResolveGateway(gw, gateways)
				if err != nil || dev == "" {
					// Missing or ambiguous gateway: do not emit allow rule.
					continue
				}
				rules = append(rules, strictEgressRule{IsV6: isV6, Source: src, Dest: subnet, OutDev: dev, Action: "RETURN"})
			}

			// 3. Terminal reject for this strict source
			rules = append(rules, strictEgressRule{IsV6: isV6, Source: src, Action: "REJECT"})
		}
	}
	return rules
}

// strictFirewallCommands generates commands to initialize or teardown the strict egress chains.
func strictFirewallCommands(cfg models.AppConfig, gateways []models.GatewayNet, add bool) []string {
	var cmds []string
	if add {
		// Initialize IPv4 chain and FORWARD jump
		cmds = append(cmds,
			fmt.Sprintf("iptables -w -N %s 2>/dev/null || true", strictChainV4),
			fmt.Sprintf("iptables -w -C FORWARD -i %s -j %s 2>/dev/null || iptables -w -I FORWARD 1 -i %s -j %s", models.WGDevice, strictChainV4, models.WGDevice, strictChainV4),
			fmt.Sprintf("iptables -w -F %s", strictChainV4),
		)
		// Initialize IPv6 chain and FORWARD jump
		cmds = append(cmds,
			fmt.Sprintf("ip6tables -w -N %s 2>/dev/null || true", strictChainV6),
			fmt.Sprintf("ip6tables -w -C FORWARD -i %s -j %s 2>/dev/null || ip6tables -w -I FORWARD 1 -i %s -j %s", models.WGDevice, strictChainV6, models.WGDevice, strictChainV6),
			fmt.Sprintf("ip6tables -w -F %s", strictChainV6),
		)

		exitNodes := enabledExitNodes(cfg)
		for _, r := range strictEgressRules(cfg, gateways, exitNodes) {
			if !r.IsV6 {
				if r.Action == "RETURN" {
					cmds = append(cmds, fmt.Sprintf("iptables -w -A %s -s %s -d %s -o %s -j RETURN", strictChainV4, r.Source, r.Dest, r.OutDev))
				} else {
					cmds = append(cmds, fmt.Sprintf("iptables -w -A %s -s %s -j REJECT --reject-with icmp-admin-prohibited", strictChainV4, r.Source))
				}
			} else {
				if r.Action == "RETURN" {
					cmds = append(cmds, fmt.Sprintf("ip6tables -w -A %s -s %s -d %s -o %s -j RETURN", strictChainV6, r.Source, r.Dest, r.OutDev))
				} else {
					cmds = append(cmds, fmt.Sprintf("ip6tables -w -A %s -s %s -j REJECT --reject-with icmp6-adm-prohibited", strictChainV6, r.Source))
				}
			}
		}
		return cmds
	}

	// Teardown
	cmds = append(cmds,
		fmt.Sprintf("iptables -w -D FORWARD -i %s -j %s 2>/dev/null || true", models.WGDevice, strictChainV4),
		fmt.Sprintf("iptables -w -F %s 2>/dev/null || true", strictChainV4),
		fmt.Sprintf("iptables -w -X %s 2>/dev/null || true", strictChainV4),
		fmt.Sprintf("ip6tables -w -D FORWARD -i %s -j %s 2>/dev/null || true", models.WGDevice, strictChainV6),
		fmt.Sprintf("ip6tables -w -F %s 2>/dev/null || true", strictChainV6),
		fmt.Sprintf("ip6tables -w -X %s 2>/dev/null || true", strictChainV6),
	)
	return cmds
}

// strictPeerSources returns all unique source selectors for enabled strict peers.
func strictPeerSources(cfg models.AppConfig) []string {
	var sources []string
	seen := make(map[string]bool)
	for _, p := range cfg.Peers {
		if !p.Enabled || !p.StrictPolicyRouting {
			continue
		}
		for _, src := range models.PeerSources(p.AllowedIPs) {
			if !seen[src] {
				seen[src] = true
				sources = append(sources, src)
			}
		}
	}
	return sources
}

func unionSources(a, b []string) []string {
	seen := make(map[string]bool)
	var res []string
	for _, s := range append(a, b...) {
		if !seen[s] {
			seen[s] = true
			res = append(res, s)
		}
	}
	return res
}

func temporaryRejectCommands(sources []string, add bool) []string {
	var cmds []string
	for _, src := range sources {
		isV6 := strings.Contains(src, ":")
		if add {
			if !isV6 {
				cmds = append(cmds, fmt.Sprintf(
					"iptables -w -I FORWARD 1 -i %s -s %s -m comment --comment '%s' -j REJECT --reject-with icmp-admin-prohibited",
					models.WGDevice, src, strictApplyComment))
			} else {
				cmds = append(cmds, fmt.Sprintf(
					"ip6tables -w -I FORWARD 1 -i %s -s %s -m comment --comment '%s' -j REJECT --reject-with icmp6-adm-prohibited",
					models.WGDevice, src, strictApplyComment))
			}
		} else {
			if !isV6 {
				cmds = append(cmds, fmt.Sprintf(
					"iptables -w -D FORWARD -i %s -s %s -m comment --comment '%s' -j REJECT --reject-with icmp-admin-prohibited 2>/dev/null || true",
					models.WGDevice, src, strictApplyComment))
			} else {
				cmds = append(cmds, fmt.Sprintf(
					"ip6tables -w -D FORWARD -i %s -s %s -m comment --comment '%s' -j REJECT --reject-with icmp6-adm-prohibited 2>/dev/null || true",
					models.WGDevice, src, strictApplyComment))
			}
		}
	}
	return cmds
}

// masqueradeRule is the NAT rule for traffic leaving over ZeroTier. Packets
// routed out a zt interface still carry their original source (a WireGuard peer
// IP, say), which the ZeroTier network has no route back to — so they are
// masqueraded behind this node's ZeroTier address.
//
// The zt+ wildcard covers every ZeroTier interface, including networks joined
// after wg0 came up, so the rule never needs to know device names.
const masqueradeSpec = "POSTROUTING -o zt+ -j MASQUERADE"

// zeroTierMasquerade returns the NAT commands for ZeroTier egress. Optional
// ACCEPT rules are inserted before MASQUERADE so advertised networks retain
// their original source addresses.
// add=false renders the teardown.
func zeroTierMasquerade(cfg models.AppConfig, gateways []models.GatewayNet, advertisedByPeer map[string][]string, add bool) []string {
	if !cfg.ZeroTier.Enabled || cfg.ZeroTier.DisableMasquerade {
		return nil
	}

	var specs []string
	if cfg.ZeroTier.ExcludeAdvertisedRoutesFromMasquerade {
		seen := make(map[string]bool)
		for peerIP, advertisedRoutes := range advertisedByPeer {
			if !strings.HasPrefix(models.DeviceForGateway(peerIP, gateways), "zt") {
				continue
			}
			for _, advertised := range advertisedRoutes {
				ip, network, err := net.ParseCIDR(strings.TrimSpace(advertised))
				if err != nil || ip.To4() == nil || seen[network.String()] {
					continue
				}
				seen[network.String()] = true
				specs = append(specs, fmt.Sprintf("-s %s -o zt+ -j ACCEPT", network.String()))
			}
		}
		sort.Strings(specs)
	}

	var commands []string
	if add {
		for _, spec := range specs {
			commands = append(commands, fmt.Sprintf(
				"iptables -t nat -C POSTROUTING %s 2>/dev/null || iptables -t nat -I POSTROUTING 1 %s",
				spec, spec))
		}
		// Check-then-add: applying twice must not stack duplicate rules, and a
		// PostDown that never ran (see ApplyConfig) would otherwise leave one behind.
		return append(commands, fmt.Sprintf(
			"iptables -t nat -C %s 2>/dev/null || iptables -t nat -A %s",
			masqueradeSpec, masqueradeSpec))
	}
	// Never fail the teardown if the rule is already gone: wg-quick runs hooks
	// under set -e, and an aborted down leaves the interface half torn down.
	commands = append(commands, fmt.Sprintf("iptables -t nat -D %s || true", masqueradeSpec))
	for _, spec := range specs {
		commands = append(commands, fmt.Sprintf("iptables -t nat -D POSTROUTING %s || true", spec))
	}
	return commands
}

// policyRouteCmd renders one policy route. The gateway decides the interface:
// a WireGuard peer IP routes over wg0, a ZeroTier peer IP over that network's
// zt* device.
//
// Every policy route is suffixed with "|| true". wg-quick runs hooks under
// `set -e`, so without it a single route the kernel refuses — a ZeroTier network
// that is not up yet, or a gateway that has stopped being on-link — would abort
// the bring-up and leave the machine with no WireGuard at all. A route that
// cannot be installed now is installed by the next apply; losing the whole
// interface is never the better failure.
func policyRouteCmd(action, subnet, gateway string, table uint, gateways []models.GatewayNet, isStrict bool) string {
	ipCommand := "ip"
	if ip, _, err := net.ParseCIDR(subnet); err == nil && ip.To4() == nil {
		ipCommand = "ip -6"
	}
	if action == "del" {
		// Deletion only needs the route key. Omitting the old gateway and device
		// also makes cleanup work immediately after process startup, before the
		// ZeroTier supervisor has rediscovered the interface that installed it.
		return fmt.Sprintf("%s route del %s table %d || true", ipCommand, subnet, table)
	}
	dev := models.DeviceForGateway(gateway, gateways)
	if dev == "" {
		if isStrict {
			// Strict policy routing must not fall back to wg0; omit route installation
			// so the peer fails closed.
			return ""
		}
		// Non-strict fallback to wg0 for best-effort compatibility.
		dev = models.WGDevice
	}
	return fmt.Sprintf("%s route %s %s via %s dev %s table %d || true", ipCommand, action, subnet, gateway, dev, table)
}

// enabledExitNodes returns the exit nodes traffic can currently be steered to,
// keyed by peer ID.
const (
	gatewayRulePriorityBase = 18000
	gatewayChainV4            = "WG_BUSY_GW_FWD4"
	gatewayChainV6            = "WG_BUSY_GW_FWD6"
	gatewayNatChainV4         = "WG_BUSY_GW_NAT4"
)

// localNetworkCIDRs are destinations that must stay on the normal LAN path
// instead of being sent through a selected VPN gateway. WG_BUSY_LAN_CIDRS can
// override the default with a comma-separated list of CIDRs.
func localNetworkCIDRs() []string {
	value := strings.TrimSpace(os.Getenv("WG_BUSY_LAN_CIDRS"))
	if value == "" {
		return []string{"192.168.178.0/24"}
	}
	var result []string
	for _, item := range strings.Split(value, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if _, _, err := net.ParseCIDR(item); err == nil {
			result = append(result, item)
		}
	}
	if len(result) == 0 {
		return []string{"192.168.178.0/24"}
	}
	return result
}

const localNetworkRulePriorityBase = 17000

type localNetworkRule struct {
	IPCommand string
	Source    string
	Dest      string
	Priority  int
}

func localNetworkRules(cfg models.AppConfig) []localNetworkRule {
	var rules []localNetworkRule
	priority := localNetworkRulePriorityBase
	for _, p := range cfg.Peers {
		if !p.Enabled {
			continue
		}
		for _, source := range models.PeerSources(p.AllowedIPs) {
			_, srcNet, srcErr := net.ParseCIDR(source)
			if srcErr != nil {
				continue
			}
			for _, dest := range localNetworkCIDRs() {
				_, dstNet, dstErr := net.ParseCIDR(dest)
				if dstErr != nil || (srcNet.IP.To4() == nil) != (dstNet.IP.To4() == nil) {
					continue
				}
				cmd := "ip"
				if dstNet.IP.To4() == nil {
					cmd = "ip -6"
				}
				rules = append(rules, localNetworkRule{
					IPCommand: cmd,
					Source: source,
					Dest: dest,
					Priority: priority,
				})
				priority++
			}
		}
	}
	// Device-specific sources must also keep local LAN destinations on the main table.
	for _, p := range cfg.Peers {
		if !p.Enabled { continue }
		for _, device := range p.DeviceRoutingRules {
			if !device.Enabled { continue }
			ip := net.ParseIP(strings.TrimSpace(device.DeviceIP))
			if ip == nil || ip.To4() == nil { continue }
			for _, dest := range localNetworkCIDRs() {
				_, dstNet, err := net.ParseCIDR(dest)
				if err != nil || dstNet.IP.To4() == nil { continue }
				rules = append(rules, localNetworkRule{IPCommand: "ip", Source: ip.String(), Dest: dest, Priority: priority})
				priority++
			}
		}
	}
	return rules
}

// vpnGatewayRule describes source-based policy routing for a peer assigned
// directly to an imported WireGuard gateway. A trailing prohibit rule makes the
// assignment fail closed if the gateway table has no usable route.
type vpnGatewayRule struct {
	IPCommand string
	Source    string
	Table     uint
	Priority  int
	Direct    bool
}

// gatewayInterfaces returns only configured gateway interfaces.
func gatewayInterfaces(cfg models.AppConfig) map[string]models.VPNGateway {
	result := make(map[string]models.VPNGateway, len(cfg.VPNGateways))
	for _, g := range cfg.VPNGateways {
		if g.Interface == "" {
			continue
		}
		result[g.ID] = g
	}
	return result
}

// vpnGatewayRules returns source rules for every enabled peer assigned to an
// enabled gateway. The lookup rule precedes a prohibit rule, so missing routes
// can never fall through into the main routing table.
func vpnGatewayRules(cfg models.AppConfig) []vpnGatewayRule {
	gateways := gatewayInterfaces(cfg)
	var rules []vpnGatewayRule
	priority := gatewayRulePriorityBase
	for _, p := range cfg.Peers {
		if !p.Enabled || strings.TrimSpace(p.VPNGatewayID) == "" {
			continue
		}
		g, ok := gateways[p.VPNGatewayID]
		if !ok || !g.Enabled || g.RoutingTableID == 0 {
			continue
		}
		for _, source := range models.PeerSources(p.AllowedIPs) {
			cmd := "ip"
			if strings.Contains(source, ":") {
				cmd = "ip -6"
			}
			rules = append(rules,
				vpnGatewayRule{IPCommand: cmd, Source: source, Table: g.RoutingTableID, Priority: priority},
				vpnGatewayRule{IPCommand: cmd, Source: source, Table: 0, Priority: priority + 1},
			)
			priority += 2
		}
	}
	return rules
}

const deviceGatewayRulePriorityBase = 16000

// peerDeviceGatewayRules returns source rules for LAN devices behind peers.
// Device-specific rules are evaluated before the peer-wide VPN gateway rule.
// An empty GatewayID means explicit direct routing via the main table.
func peerDeviceGatewayRules(cfg models.AppConfig) []vpnGatewayRule {
	gateways := gatewayInterfaces(cfg)
	var rules []vpnGatewayRule
	priority := deviceGatewayRulePriorityBase
	for _, p := range cfg.Peers {
		if !p.Enabled {
			continue
		}
		for _, device := range p.DeviceRoutingRules {
			if !device.Enabled || net.ParseIP(strings.TrimSpace(device.DeviceIP)) == nil {
				continue
			}
			ip := net.ParseIP(strings.TrimSpace(device.DeviceIP))
			if ip.To4() == nil {
				continue
			}
			if strings.TrimSpace(device.GatewayID) == "" {
				rules = append(rules, vpnGatewayRule{IPCommand: "ip", Source: ip.String(), Direct: true, Priority: priority})
				priority++
				continue
			}
			g, ok := gateways[device.GatewayID]
			if !ok || !g.Enabled || g.RoutingTableID == 0 {
				// Invalid assignment fails closed instead of falling through to the
				// peer-wide gateway or the host main table.
				rules = append(rules,
					vpnGatewayRule{IPCommand: "ip", Source: ip.String(), Table: 0, Priority: priority},
				)
				priority++
				continue
			}
			rules = append(rules,
				vpnGatewayRule{IPCommand: "ip", Source: ip.String(), Table: g.RoutingTableID, Priority: priority},
				vpnGatewayRule{IPCommand: "ip", Source: ip.String(), Table: 0, Priority: priority + 1},
			)
			priority += 2
		}
	}
	return rules
}

// gatewayRouteCommands creates or removes a default route (or IPv6 default
// route) in each gateway's dedicated policy table. Table=off is used in the
// imported wg-quick config so these routes never become the host's main route.
func gatewayRouteCommands(cfg models.AppConfig, action string) []string {
	var cmds []string
	for _, g := range cfg.VPNGateways {
		if g.Interface == "" || g.RoutingTableID == 0 {
			continue
		}
		hasV4, hasV6 := false, false
		for _, allowed := range strings.Split(g.AllowedIPs, ",") {
			_, n, err := net.ParseCIDR(strings.TrimSpace(allowed))
			if err != nil {
				continue
			}
			if n.IP.To4() != nil {
				if n.String() == "0.0.0.0/0" {
					hasV4 = true
				}
			} else if n.String() == "::/0" {
				hasV6 = true
			}
		}
		if hasV4 {
			// WireGuard's encrypted endpoint itself must stay reachable via the
			// main table. Table=off prevents the imported config from changing it;
			// this policy table is only used after source-based selection.
			cmd := fmt.Sprintf("ip route %s default dev %s table %d", action, g.Interface, g.RoutingTableID)
			// Gateway interfaces are started by gateway.Manager after wg0. A route
			// hook during wg0 startup may therefore run before the interface exists;
			// ReapplyRouting installs it once the gateway is up.
			if action == "del" || action == "replace" {
				cmd += " 2>/dev/null || true"
			}
			cmds = append(cmds, cmd)
		}
		if hasV6 {
			cmd := fmt.Sprintf("ip -6 route %s default dev %s table %d", action, g.Interface, g.RoutingTableID)
			if action == "del" || action == "replace" {
				cmd += " 2>/dev/null || true"
			}
			cmds = append(cmds, cmd)
		}
	}
	return cmds
}

func gatewayFirewallCommands(cfg models.AppConfig, add bool) []string {
	var cmds []string
	if add {
		cmds = append(cmds,
			fmt.Sprintf("iptables -w -N %s 2>/dev/null || true", gatewayChainV4),
			fmt.Sprintf("iptables -w -F %s", gatewayChainV4),
			fmt.Sprintf("iptables -w -C FORWARD -i %s -j %s 2>/dev/null || iptables -w -I FORWARD 1 -i %s -j %s", models.WGDevice, gatewayChainV4, models.WGDevice, gatewayChainV4),
			fmt.Sprintf("iptables -t nat -w -N %s 2>/dev/null || true", gatewayNatChainV4),
			fmt.Sprintf("iptables -t nat -w -F %s", gatewayNatChainV4),
			fmt.Sprintf("iptables -t nat -w -C POSTROUTING -j %s 2>/dev/null || iptables -t nat -w -I POSTROUTING 1 -j %s", gatewayNatChainV4, gatewayNatChainV4),
			fmt.Sprintf("ip6tables -w -N %s 2>/dev/null || true", gatewayChainV6),
			fmt.Sprintf("ip6tables -w -F %s", gatewayChainV6),
			fmt.Sprintf("ip6tables -w -C FORWARD -i %s -j %s 2>/dev/null || ip6tables -w -I FORWARD 1 -i %s -j %s", models.WGDevice, gatewayChainV6, models.WGDevice, gatewayChainV6),
		)

		gateways := gatewayInterfaces(cfg)

		// LAN traffic remains reachable for all WireGuard peers, including peers
		// assigned to a VPN gateway. MASQUERADE gives LAN hosts a return path.
		for _, p := range cfg.Peers {
			if !p.Enabled {
				continue
			}
			for _, source := range models.PeerSources(p.AllowedIPs) {
				if strings.Contains(source, ":") {
					continue
				}
				for _, dest := range localNetworkCIDRs() {
					if strings.Contains(dest, ":") {
						continue
					}
					cmds = append(cmds,
						fmt.Sprintf("iptables -w -A %s -s %s -d %s -j ACCEPT", gatewayChainV4, source, dest),
						fmt.Sprintf("iptables -t nat -w -A %s -s %s -d %s -j MASQUERADE", gatewayNatChainV4, source, dest),
						fmt.Sprintf("iptables -w -A %s -d %s -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT", gatewayChainV4, dest),
					)
				}
			}
		}

		for _, p := range cfg.Peers {
			if !p.Enabled || p.VPNGatewayID == "" {
				continue
			}
			g, ok := gateways[p.VPNGatewayID]
			if !ok || !g.Enabled || g.Interface == "" {
				continue
			}
			for _, source := range models.PeerSources(p.AllowedIPs) {
				if strings.Contains(source, ":") {
					cmds = append(cmds,
						fmt.Sprintf("ip6tables -w -A %s -s %s -o %s -j ACCEPT", gatewayChainV6, source, g.Interface),
						fmt.Sprintf("ip6tables -w -A %s -s %s -o %s -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT", gatewayChainV6, source, models.WGDevice),
					)
				} else {
					cmds = append(cmds,
						fmt.Sprintf("iptables -w -A %s -s %s -o %s -j ACCEPT", gatewayChainV4, source, g.Interface),
						fmt.Sprintf("iptables -w -A %s -s %s -o %s -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT", gatewayChainV4, source, models.WGDevice),
						fmt.Sprintf("iptables -t nat -w -A %s -s %s -o %s -j MASQUERADE", gatewayNatChainV4, source, g.Interface),
					)
				}
			}
		}
		// Device-specific gateway assignments need the same forwarding and NAT
		// permissions as a peer-wide gateway assignment.
		for _, p := range cfg.Peers {
			if !p.Enabled { continue }
			for _, device := range p.DeviceRoutingRules {
				if !device.Enabled || device.GatewayID == "" { continue }
				g, ok := gateways[device.GatewayID]
				if !ok || !g.Enabled || g.Interface == "" { continue }
				ip := net.ParseIP(strings.TrimSpace(device.DeviceIP))
				if ip == nil || ip.To4() == nil { continue }
				cmds = append(cmds,
					fmt.Sprintf("iptables -w -A %s -s %s -o %s -j ACCEPT", gatewayChainV4, ip.String(), g.Interface),
					fmt.Sprintf("iptables -w -A %s -s %s -o %s -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT", gatewayChainV4, ip.String(), models.WGDevice),
					fmt.Sprintf("iptables -t nat -w -A %s -s %s -o %s -j MASQUERADE", gatewayNatChainV4, ip.String(), g.Interface),
				)
			}
		}
		return cmds
	}

	return []string{
		fmt.Sprintf("iptables -w -D FORWARD -i %s -j %s 2>/dev/null || true", models.WGDevice, gatewayChainV4),
		fmt.Sprintf("iptables -w -F %s 2>/dev/null || true", gatewayChainV4),
		fmt.Sprintf("iptables -w -X %s 2>/dev/null || true", gatewayChainV4),
		fmt.Sprintf("iptables -t nat -w -D POSTROUTING -j %s 2>/dev/null || true", gatewayNatChainV4),
		fmt.Sprintf("iptables -t nat -w -F %s 2>/dev/null || true", gatewayNatChainV4),
		fmt.Sprintf("iptables -t nat -w -X %s 2>/dev/null || true", gatewayNatChainV4),
		fmt.Sprintf("ip6tables -w -D FORWARD -i %s -j %s 2>/dev/null || true", models.WGDevice, gatewayChainV6),
		fmt.Sprintf("ip6tables -w -F %s 2>/dev/null || true", gatewayChainV6),
		fmt.Sprintf("ip6tables -w -X %s 2>/dev/null || true", gatewayChainV6),
	}
}

func enabledExitNodes(cfg models.AppConfig) map[string]models.Peer {
	exitNodes := make(map[string]models.Peer)
	for _, p := range cfg.Peers {
		if p.IsExitNode && p.Enabled && p.RoutingTableID > 0 {
			exitNodes[p.ID] = p
		}
	}
	return exitNodes
}

// exitNodeRouteCmds renders the routing table entries for each exit node.
// action is "replace" on the way up and "del" on the way down.
func exitNodeRouteCmds(action string, exitNodes map[string]models.Peer) []string {
	var cmds []string
	done := make(map[uint]bool)
	for _, exitNode := range exitNodes {
		if done[exitNode.RoutingTableID] {
			continue
		}
		if exitNode.ExitNodeAllowAll {
			for _, ipCommand := range []string{"ip -4", "ip -6"} {
				cmd := fmt.Sprintf("%s route %s default dev wg0 table %d", ipCommand, action, exitNode.RoutingTableID)
				if action == "del" {
					cmd += " || true"
				}
				cmds = append(cmds, cmd)
			}
		} else {
			for _, route := range exitNode.ExitNodeRoutes {
				if route != "" {
					ipCommand := "ip -4"
					if ip, _, err := net.ParseCIDR(route); err == nil && ip.To4() == nil {
						ipCommand = "ip -6"
					}
					cmd := fmt.Sprintf("%s route %s %s dev wg0 table %d", ipCommand, action, route, exitNode.RoutingTableID)
					if action == "del" {
						cmd += " || true"
					}
					cmds = append(cmds, cmd)
				}
			}
		}
		done[exitNode.RoutingTableID] = true
	}
	return cmds
}

// policyRouteCmds renders the routes populating each peer's own policy table.
func policyRouteCmds(action string, cfg models.AppConfig, gateways []models.GatewayNet) []string {
	var cmds []string
	for _, p := range cfg.Peers {
		if !p.Enabled || len(p.PolicyRoutes) == 0 || p.PolicyRoutingTableID == 0 {
			continue
		}
		if len(models.PeerIPs(p.AllowedIPs)) == 0 {
			continue
		}

		for _, routeStr := range p.PolicyRoutes {
			parts := strings.Split(routeStr, " via ")
			if len(parts) == 2 {
				cmd := policyRouteCmd(action, strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]), p.PolicyRoutingTableID, gateways, p.StrictPolicyRouting)
				if cmd != "" {
					cmds = append(cmds, cmd)
				}
			}
		}
	}
	return cmds
}

// GeneratePostUpCommands returns ip rule/route commands for wg0.conf PostUp.
// Order: first create routing tables for exit nodes, then add rules for peers.
// gateways are the on-link networks policy route gateways may point into.
func GeneratePostUpCommands(cfg models.AppConfig, gateways []models.GatewayNet) []string {
	return generatePostUpCommands(cfg, gateways, nil)
}

// GeneratePostUpCommandsWithBGP renders routing hooks using the routes
// currently present in each peer's BGP Adj-RIB-Out.
func GeneratePostUpCommandsWithBGP(cfg models.AppConfig, gateways []models.GatewayNet, advertisedByPeer map[string][]string) []string {
	return generatePostUpCommands(cfg, gateways, advertisedByPeer)
}

func generatePostUpCommands(cfg models.AppConfig, gateways []models.GatewayNet, advertisedByPeer map[string][]string) []string {
	exitNodes := enabledExitNodes(cfg)

	// No early return when there are no exit nodes: custom policy routes are
	// independent of them and must still be emitted.
	cmds := exitNodeRouteCmds("replace", exitNodes)
	cmds = append(cmds, gatewayRouteCommands(cfg, "replace")...)
	cmds = append(cmds, gatewayFirewallCommands(cfg, true)...)

	// NAT for anything leaving over ZeroTier.
	cmds = append(cmds, zeroTierMasquerade(cfg, gateways, advertisedByPeer, true)...)

	// Strict egress firewall chains and rules.
	cmds = append(cmds, strictFirewallCommands(cfg, gateways, true)...)

	// LAN destinations bypass source-based VPN gateway routing and use the main table.
	for _, r := range localNetworkRules(cfg) {
		cmds = append(cmds, fmt.Sprintf("%s rule del priority %d 2>/dev/null || true; %s rule add from %s to %s table main priority %d",
			r.IPCommand, r.Priority, r.IPCommand, r.Source, r.Dest, r.Priority))
	}

	// Source-based rules for peers assigned to imported VPN gateways.
	// These are deliberately after LAN bypass rules so local networks stay on
	// the normal path, and before the main table (32766) so internet traffic
	// follows the selected gateway. The trailing prohibit rule prevents fallback.
	for _, r := range append(vpnGatewayRules(cfg), peerDeviceGatewayRules(cfg)...) {
		if r.Direct {
			cmds = append(cmds, fmt.Sprintf("%s rule del priority %d 2>/dev/null || true; %s rule add from %s table main priority %d",
				r.IPCommand, r.Priority, r.IPCommand, r.Source, r.Priority))
		} else if r.Table == 0 {
			cmds = append(cmds, fmt.Sprintf("%s rule del priority %d 2>/dev/null || true; %s rule add from %s prohibit priority %d",
				r.IPCommand, r.Priority, r.IPCommand, r.Source, r.Priority))
		} else {
			cmds = append(cmds, fmt.Sprintf("%s rule del priority %d 2>/dev/null || true; %s rule add from %s table %d priority %d",
				r.IPCommand, r.Priority, r.IPCommand, r.Source, r.Table, r.Priority))
		}
	}

	// Policy rules for exit nodes, policy routes, and strict rejects.
	//
	// Each add is preceded by a delete of whatever holds that priority: `ip rule
	// add ... priority N` fails with EEXIST if the slot is taken, and wg-quick
	// runs hooks under `set -e`, so a leftover rule from a teardown that never
	// ran would abort the whole interface bring-up. Deleting by priority alone
	// also clears a stale rule whose selector has since changed.
	for _, r := range peerRules(cfg, exitNodes) {
		cmds = append(cmds, fmt.Sprintf("%s rule del priority %d 2>/dev/null || true; %s rule add %s %s priority %d",
			r.IPCommand, r.Priority, r.IPCommand, r.Selector, r.Action, r.Priority))
	}

	// Add the routes that populate each peer's own policy table.
	return append(cmds, policyRouteCmds("replace", cfg, gateways)...)
}

func applyCommands(cmds []string) error {
	for _, cmd := range cmds {
		if out, err := runShellCommand(cmd); err != nil {
			return fmt.Errorf("%s: %v: %s", cmd, err, strings.TrimSpace(string(out)))
		}
	}
	return nil
}

// Reconcile safely converges live routing and firewall state from previous to next.
// Strict policy routing reconciliation is fail-closed: affected strict sources are
// blocked by temporary FORWARD reject rules before any previous state is altered,
// and the temporary reject rules are removed only after the entire next state has
// applied successfully.
func Reconcile(previous models.AppConfig, previousGateways []models.GatewayNet, previousAdvertised map[string][]string, next models.AppConfig, nextGateways []models.GatewayNet, nextAdvertised map[string][]string) error {
	if !interfaceUp() {
		return nil
	}

	affectedStrictSources := unionSources(strictPeerSources(previous), strictPeerSources(next))

	// Step 1: Install temporary reject rules for all affected strict sources
	if len(affectedStrictSources) > 0 {
		if err := applyCommands(temporaryRejectCommands(affectedStrictSources, true)); err != nil {
			return fmt.Errorf("installing temporary strict guards: %w", err)
		}
	}

	// Step 2: Remove previous routing state (masquerade bypasses, rules, routes)
	previousExitNodes := enabledExitNodes(previous)
	var teardownCmds []string
	teardownCmds = append(teardownCmds, zeroTierMasquerade(previous, previousGateways, previousAdvertised, false)...)
	for _, r := range peerRules(previous, previousExitNodes) {
		teardownCmds = append(teardownCmds, fmt.Sprintf("%s rule del %s %s priority %d || true", r.IPCommand, r.Selector, r.Action, r.Priority))
	}
	teardownCmds = append(teardownCmds, gatewayFirewallCommands(previous, false)...)
	for _, r := range localNetworkRules(previous) {
		teardownCmds = append(teardownCmds, fmt.Sprintf("%s rule del from %s to %s table main priority %d || true", r.IPCommand, r.Source, r.Dest, r.Priority))
	}
	for _, r := range append(vpnGatewayRules(previous), peerDeviceGatewayRules(previous)...) {
		if r.Direct {
			teardownCmds = append(teardownCmds, fmt.Sprintf("%s rule del from %s table main priority %d || true", r.IPCommand, r.Source, r.Priority))
		} else if r.Table == 0 {
			teardownCmds = append(teardownCmds, fmt.Sprintf("%s rule del from %s prohibit priority %d || true", r.IPCommand, r.Source, r.Priority))
		} else {
			teardownCmds = append(teardownCmds, fmt.Sprintf("%s rule del from %s table %d priority %d || true", r.IPCommand, r.Source, r.Table, r.Priority))
		}
	}
	teardownCmds = append(teardownCmds, gatewayRouteCommands(previous, "del")...)
	teardownCmds = append(teardownCmds, exitNodeRouteCmds("del", previousExitNodes)...)
	teardownCmds = append(teardownCmds, policyRouteCmds("del", previous, previousGateways)...)
	if err := applyCommands(teardownCmds); err != nil {
		return fmt.Errorf("removing previous routing state: %w", err)
	}

	// Step 3: Refresh permanent strict egress chains
	if err := applyCommands(strictFirewallCommands(next, nextGateways, true)); err != nil {
		return fmt.Errorf("updating strict firewall chains: %w", err)
	}

	// Step 4: Install next routing state (exit node routes, masquerade, rules, routes)
	nextExitNodes := enabledExitNodes(next)
	var setupCmds []string
	setupCmds = append(setupCmds, exitNodeRouteCmds("replace", nextExitNodes)...)
	setupCmds = append(setupCmds, gatewayRouteCommands(next, "replace")...)
	setupCmds = append(setupCmds, gatewayFirewallCommands(next, true)...)
	setupCmds = append(setupCmds, zeroTierMasquerade(next, nextGateways, nextAdvertised, true)...)
	for _, r := range localNetworkRules(next) {
		setupCmds = append(setupCmds, fmt.Sprintf("%s rule del priority %d 2>/dev/null || true; %s rule add from %s to %s table main priority %d",
			r.IPCommand, r.Priority, r.IPCommand, r.Source, r.Dest, r.Priority))
	}
	for _, r := range append(vpnGatewayRules(next), peerDeviceGatewayRules(next)...) {
		if r.Direct {
			setupCmds = append(setupCmds, fmt.Sprintf("%s rule del priority %d 2>/dev/null || true; %s rule add from %s table main priority %d", r.IPCommand, r.Priority, r.IPCommand, r.Source, r.Priority))
		} else if r.Table == 0 {
			setupCmds = append(setupCmds, fmt.Sprintf("%s rule del priority %d 2>/dev/null || true; %s rule add from %s prohibit priority %d", r.IPCommand, r.Priority, r.IPCommand, r.Source, r.Priority))
		} else {
			setupCmds = append(setupCmds, fmt.Sprintf("%s rule del priority %d 2>/dev/null || true; %s rule add from %s table %d priority %d", r.IPCommand, r.Priority, r.IPCommand, r.Source, r.Table, r.Priority))
		}
	}
	for _, r := range peerRules(next, nextExitNodes) {
		setupCmds = append(setupCmds, fmt.Sprintf("%s rule del priority %d 2>/dev/null || true; %s rule add %s %s priority %d",
			r.IPCommand, r.Priority, r.IPCommand, r.Selector, r.Action, r.Priority))
	}
	setupCmds = append(setupCmds, policyRouteCmds("replace", next, nextGateways)...)
	if err := applyCommands(setupCmds); err != nil {
		return fmt.Errorf("installing new routing state: %w", err)
	}

	// Step 5: If all applied successfully, remove temporary reject rules
	if len(affectedStrictSources) > 0 {
		if err := applyCommands(temporaryRejectCommands(affectedStrictSources, false)); err != nil {
			return fmt.Errorf("removing temporary strict guards: %w", err)
		}
	}

	return nil
}

// GeneratePostDownCommands returns cleanup commands for wg0.conf PostDown.
// Order: first remove rules, then remove routing tables (reverse of PostUp).
func GeneratePostDownCommands(cfg models.AppConfig, gateways []models.GatewayNet) []string {
	return generatePostDownCommands(cfg, gateways, nil)
}

// GeneratePostDownCommandsWithBGP removes routing hooks rendered from the
// routes currently present in each peer's BGP Adj-RIB-Out.
func GeneratePostDownCommandsWithBGP(cfg models.AppConfig, gateways []models.GatewayNet, advertisedByPeer map[string][]string) []string {
	return generatePostDownCommands(cfg, gateways, advertisedByPeer)
}

func generatePostDownCommands(cfg models.AppConfig, gateways []models.GatewayNet, advertisedByPeer map[string][]string) []string {
	exitNodes := enabledExitNodes(cfg)

	// No early return when there are no exit nodes: custom policy routes are
	// independent of them and must still be emitted.
	cmds := zeroTierMasquerade(cfg, gateways, advertisedByPeer, false)

	// Remove LAN bypass rules first.
	for _, r := range localNetworkRules(cfg) {
		cmds = append(cmds, fmt.Sprintf("%s rule del from %s to %s table main priority %d || true", r.IPCommand, r.Source, r.Dest, r.Priority))
	}

	// Remove source-based VPN gateway rules first.
	for _, r := range append(vpnGatewayRules(cfg), peerDeviceGatewayRules(cfg)...) {
		if r.Direct {
			cmds = append(cmds, fmt.Sprintf("%s rule del from %s table main priority %d || true", r.IPCommand, r.Source, r.Priority))
		} else if r.Table == 0 {
			cmds = append(cmds, fmt.Sprintf("%s rule del from %s prohibit priority %d || true", r.IPCommand, r.Source, r.Priority))
		} else {
			cmds = append(cmds, fmt.Sprintf("%s rule del from %s table %d priority %d || true", r.IPCommand, r.Source, r.Table, r.Priority))
		}
	}

	// Remove policy rules first. Deleting by priority is exact, so repeated
	// apply cycles cannot leave duplicates behind.
	for _, r := range peerRules(cfg, exitNodes) {
		cmds = append(cmds, fmt.Sprintf("%s rule del %s %s priority %d || true", r.IPCommand, r.Selector, r.Action, r.Priority))
	}

	// Remove gateway default routes.
	cmds = append(cmds, gatewayRouteCommands(cfg, "del")...)

	// Remove routing tables.
	cmds = append(cmds, exitNodeRouteCmds("del", exitNodes)...)

	// Remove the routes from each peer's own policy table.
	cmds = append(cmds, policyRouteCmds("del", cfg, gateways)...)

	// Strict firewall teardown.
	return append(cmds, strictFirewallCommands(cfg, gateways, false)...)
}
