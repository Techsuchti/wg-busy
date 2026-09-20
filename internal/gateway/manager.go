package gateway

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/yix/wg-busy/internal/models"
)

const (
	interfacePrefix = "wgout"
	tableBase       = 20000
)

type Status struct {
	ID              string
	Name            string
	Interface       string
	Enabled         bool
	Running         bool
	LastError       string
	LastChange      time.Time
	Endpoint        string
	LatestHandshake time.Time
	ReceiveBytes    int64
	TransmitBytes   int64
	PeerCount       int
}

type Manager struct {
	mu       sync.Mutex
	configDir string
	status   map[string]Status
}

func NewManager(configDir string) *Manager {
	return &Manager{
		configDir: configDir,
		status:    make(map[string]Status),
	}
}

func SafeInterfaceName(id string) string {
	id = strings.ToLower(strings.TrimSpace(id))
	if len(id) > 8 {
		id = id[:8]
	}
	name := interfacePrefix + id
	if len(name) > 15 {
		name = name[:15]
	}
	return name
}

func ConfigPath(dir, iface string) string {
	return strings.TrimRight(dir, "/") + "/" + iface + ".conf"
}

func ParseConfig(raw string) (models.VPNGateway, error) {
	var g models.VPNGateway
	section := ""
	peers := 0
	scan := func(s string) error {
		s = strings.TrimSpace(strings.TrimSuffix(s, "\r"))
		if s == "" || strings.HasPrefix(s, "#") || strings.HasPrefix(s, ";") {
			return nil
		}
		if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
			section = strings.ToLower(strings.TrimSpace(s[1 : len(s)-1]))
			if section != "interface" && section != "peer" {
				return fmt.Errorf("unsupported section %q", section)
			}
			if section == "peer" {
				peers++
				if peers > 1 {
					return errors.New("gateway config must contain exactly one [Peer] section")
				}
			}
			return nil
		}
		idx := strings.IndexByte(s, '=')
		if idx < 1 {
			return fmt.Errorf("invalid line %q", s)
		}
		key := strings.ToLower(strings.TrimSpace(s[:idx]))
		value := strings.TrimSpace(s[idx+1:])
		if section == "" {
			return errors.New("configuration must start with [Interface]")
		}
		switch section {
		case "interface":
			switch key {
			case "privatekey":
				g.PrivateKey = value
			case "address":
				g.Address = value
			case "mtu":
				n, err := strconv.ParseUint(value, 10, 16)
				if err != nil {
					return fmt.Errorf("invalid MTU: %w", err)
				}
				g.MTU = uint16(n)
			case "dns":
				g.DNS = value
			case "listenport", "table", "fwmark", "preup", "postup", "predown", "postdown":
				// These options are intentionally ignored for upstream gateways.
				// In particular, arbitrary hooks must never be executed from an upload.
			default:
				return fmt.Errorf("unsupported [Interface] option %q", key)
			}
		case "peer":
			switch key {
			case "publickey":
				g.PublicKey = value
			case "presharedkey":
				g.PresharedKey = value
			case "allowedips":
				g.AllowedIPs = value
			case "endpoint":
				g.Endpoint = value
			case "persistentkeepalive":
				n, err := strconv.ParseUint(value, 10, 16)
				if err != nil {
					return fmt.Errorf("invalid PersistentKeepalive: %w", err)
				}
				g.PersistentKeepalive = uint16(n)
			case "replaceallowedips":
				// Accepted by some configs, but not required for the rendered client.
			default:
				return fmt.Errorf("unsupported [Peer] option %q", key)
			}
		}
		return nil
	}

	lines := strings.Split(raw, "\n")
	for _, line := range lines {
		if err := scan(line); err != nil {
			return models.VPNGateway{}, err
		}
	}
	if section != "peer" {
		return models.VPNGateway{}, errors.New("configuration is missing [Peer]")
	}
	if g.PrivateKey == "" || g.Address == "" || g.PublicKey == "" || g.AllowedIPs == "" || g.Endpoint == "" {
		return models.VPNGateway{}, errors.New("configuration requires PrivateKey, Address, Peer PublicKey, AllowedIPs and Endpoint")
	}
	if !modelsValidKey(g.PrivateKey) || !modelsValidKey(g.PublicKey) {
		return models.VPNGateway{}, errors.New("invalid WireGuard key")
	}
	if g.PresharedKey != "" && !modelsValidKey(g.PresharedKey) {
		return models.VPNGateway{}, errors.New("invalid PresharedKey")
	}
	if !modelsValidCIDRs(g.Address) || !modelsValidCIDRs(g.AllowedIPs) {
		return models.VPNGateway{}, errors.New("invalid Address or AllowedIPs")
	}
	if !modelsValidEndpoint(g.Endpoint) {
		return models.VPNGateway{}, errors.New("invalid Endpoint")
	}
	return g, nil
}

func modelsValidKey(s string) bool {
	s = strings.TrimSpace(s)
	if len(s) != 44 {
		return false
	}
	_, err := base64.StdEncoding.DecodeString(s)
	return err == nil
}

func modelsValidCIDRs(s string) bool {
	for _, part := range strings.Split(s, ",") {
		if strings.TrimSpace(part) == "" {
			return false
		}
		if _, _, err := net.ParseCIDR(strings.TrimSpace(part)); err != nil {
			return false
		}
	}
	return true
}

func modelsValidEndpoint(s string) bool {
	host, port, err := net.SplitHostPort(strings.TrimSpace(s))
	if err != nil || host == "" {
		return false
	}
	n, err := strconv.Atoi(port)
	return err == nil && n > 0 && n <= 65535
}

func (m *Manager) Render(g models.VPNGateway) (string, error) {
	if g.Interface == "" {
		g.Interface = SafeInterfaceName(g.ID)
	}
	if err := g.ValidateVPNGateway(); err != nil {
		return "", err
	}
	// Do not copy arbitrary hooks or Table/FwMark from imported configs.
	// Table=off prevents an imported full-tunnel config from replacing the
	// Unraid container's main default route.
	var b strings.Builder
	b.WriteString("[Interface]\n")
	b.WriteString("PrivateKey = " + g.PrivateKey + "\n")
	b.WriteString("Address = " + g.Address + "\n")
	if g.MTU != 0 {
		b.WriteString("MTU = " + strconv.Itoa(int(g.MTU)) + "\n")
	}
	b.WriteString("Table = off\n\n")
	b.WriteString("[Peer]\n")
	b.WriteString("PublicKey = " + g.PublicKey + "\n")
	if g.PresharedKey != "" {
		b.WriteString("PresharedKey = " + g.PresharedKey + "\n")
	}
	b.WriteString("AllowedIPs = " + g.AllowedIPs + "\n")
	b.WriteString("Endpoint = " + g.Endpoint + "\n")
	if g.PersistentKeepalive != 0 {
		b.WriteString("PersistentKeepalive = " + strconv.Itoa(int(g.PersistentKeepalive)) + "\n")
	}
	return b.String(), nil
}

func command(name string, args ...string) ([]byte, error) {
	return exec.Command(name, args...).CombinedOutput()
}

func ensurePolicyRoutes(g models.VPNGateway) error {
	if g.Interface == "" || g.RoutingTableID == 0 {
		return nil
	}

	// Keep the upstream WireGuard endpoint reachable through the host's normal
	// uplink. The selected peer traffic is policy-routed through the gateway,
	// but the encrypted gateway transport itself must never recurse into the
	// gateway tunnel.
	host, _, err := net.SplitHostPort(strings.TrimSpace(g.Endpoint))
	if err == nil {
		if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil {
			out, routeErr := command("ip", "-4", "route", "get", ip.String())
			if ip.To4() != nil && routeErr == nil {
				fields := strings.Fields(string(out))
				dev, via := "", ""
				for i := 0; i < len(fields); i++ {
					if fields[i] == "dev" && i+1 < len(fields) {
						dev = fields[i+1]
					}
					if fields[i] == "via" && i+1 < len(fields) {
						via = fields[i+1]
					}
				}
				if dev != "" && dev != g.Interface {
					args := []string{"route", "replace", ip.String() + "/32"}
					if via != "" {
						args = append(args, "via", via)
					}
					args = append(args, "dev", dev)
					if out, err := command("ip", args...); err != nil {
						return fmt.Errorf("installing gateway endpoint route for %s: %s: %w", g.Name, strings.TrimSpace(string(out)), err)
					}
				}
			}
		}
	}

	for _, allowed := range strings.Split(g.AllowedIPs, ",") {
		allowed = strings.TrimSpace(allowed)
		_, network, err := net.ParseCIDR(allowed)
		if err != nil {
			continue
		}
		if network.String() == "0.0.0.0/0" {
			if out, err := command("ip", "route", "replace", "default", "dev", g.Interface, "table", strconv.FormatUint(uint64(g.RoutingTableID), 10)); err != nil {
				return fmt.Errorf("installing IPv4 gateway route for %s: %s: %w", g.Name, strings.TrimSpace(string(out)), err)
			}
		}
		if network.String() == "::/0" {
			if out, err := command("ip", "-6", "route", "replace", "default", "dev", g.Interface, "table", strconv.FormatUint(uint64(g.RoutingTableID), 10)); err != nil {
				return fmt.Errorf("installing IPv6 gateway route for %s: %s: %w", g.Name, strings.TrimSpace(string(out)), err)
			}
		}
	}
	return nil
}

func (m *Manager) Start(g models.VPNGateway) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !g.Enabled {
		return m.stopLocked(g)
	}
	iface := g.Interface
	if iface == "" {
		iface = SafeInterfaceName(g.ID)
		g.Interface = iface
	}
	rendered, err := m.Render(g)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(m.configDir, 0700); err != nil {
		return err
	}
	path := ConfigPath(m.configDir, iface)
	if err := os.WriteFile(path, []byte(rendered), 0600); err != nil {
		return err
	}
	_, _ = command("wg-quick", "down", path)
	out, err := command("wg-quick", "up", path)
	if err != nil {
		return fmt.Errorf("starting gateway %s: %s: %w", g.Name, strings.TrimSpace(string(out)), err)
	}
	if err := ensurePolicyRoutes(g); err != nil {
		_, _ = command("wg-quick", "down", path)
		m.status[g.ID] = Status{ID: g.ID, Name: g.Name, Interface: iface, Enabled: true, Running: false, LastError: err.Error(), Endpoint: g.Endpoint, LastChange: time.Now().UTC()}
		return err
	}
	m.status[g.ID] = Status{ID: g.ID, Name: g.Name, Interface: iface, Enabled: true, Running: true, Endpoint: g.Endpoint, LastChange: time.Now().UTC()}
	return nil
}

func (m *Manager) stopLocked(g models.VPNGateway) error {
	iface := g.Interface
	if iface == "" {
		iface = SafeInterfaceName(g.ID)
	}
	path := ConfigPath(m.configDir, iface)
	_, _ = command("wg-quick", "down", path)
	m.status[g.ID] = Status{ID: g.ID, Name: g.Name, Interface: iface, Enabled: false, Running: false, Endpoint: g.Endpoint, LastChange: time.Now().UTC()}
	return nil
}

func (m *Manager) Stop(g models.VPNGateway) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.stopLocked(g)
}

func (m *Manager) Status(id string) Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.status[id]
	if s.Interface == "" {
		return s
	}
	if _, err := command("ip", "link", "show", "dev", s.Interface); err == nil {
		s.Running = true
	} else {
		s.Running = false
		return s
	}

	// Read-only WireGuard telemetry is used for the dashboard and diagnostics.
	// Never expose private or preshared keys through Status.
	latest, latestErr := command("wg", "show", s.Interface, "latest-handshakes")
	transfers, transferErr := command("wg", "show", s.Interface, "transfer")
	if latestErr == nil {
		for _, line := range strings.Split(strings.TrimSpace(string(latest)), "\n") {
			fields := strings.Fields(line)
			if len(fields) != 2 {
				continue
			}
			sec, err := strconv.ParseInt(fields[1], 10, 64)
			if err == nil && sec > 0 {
				ts := time.Unix(sec, 0)
				if ts.After(s.LatestHandshake) {
					s.LatestHandshake = ts
				}
			}
		}
	}
	if transferErr == nil {
		for _, line := range strings.Split(strings.TrimSpace(string(transfers)), "\n") {
			fields := strings.Fields(line)
			if len(fields) != 3 {
				continue
			}
			rx, rxErr := strconv.ParseInt(fields[1], 10, 64)
			tx, txErr := strconv.ParseInt(fields[2], 10, 64)
			if rxErr == nil && txErr == nil {
				s.ReceiveBytes += rx
				s.TransmitBytes += tx
				s.PeerCount++
			}
		}
	}
	return s
}

func (m *Manager) Reconcile(cfg models.AppConfig) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Reserve deterministic routing-table IDs for imported uplinks. The IDs are
	// intentionally outside the range used by wg-busy's exit-node tables.
	usedTables := make(map[uint]bool)
	for _, g := range cfg.VPNGateways {
		if g.RoutingTableID > 0 {
			usedTables[g.RoutingTableID] = true
		}
	}

	nextTable := uint(tableBase)
	for i := range cfg.VPNGateways {
		if cfg.VPNGateways[i].RoutingTableID != 0 {
			continue
		}
		for usedTables[nextTable] {
			nextTable++
		}
		cfg.VPNGateways[i].RoutingTableID = nextTable
		usedTables[nextTable] = true
		nextTable++
	}

	desired := make(map[string]models.VPNGateway, len(cfg.VPNGateways))
	for _, g := range cfg.VPNGateways {
		desired[g.ID] = g
		if g.Interface == "" {
			g.Interface = SafeInterfaceName(g.ID)
		}
		if !g.Enabled || !g.AutoStart {
			_ = m.stopLocked(g)
			continue
		}
		rendered, err := m.Render(g)
		if err != nil {
			m.status[g.ID] = Status{ID:g.ID, Name:g.Name, Interface:g.Interface, Enabled:true, Running:false, LastError:err.Error(), Endpoint:g.Endpoint, LastChange:time.Now().UTC()}
			continue
		}
		if err := os.MkdirAll(m.configDir, 0700); err != nil {
			m.status[g.ID] = Status{ID:g.ID, Name:g.Name, Interface:g.Interface, Enabled:true, Running:false, LastError:err.Error(), Endpoint:g.Endpoint, LastChange:time.Now().UTC()}
			continue
		}
		path := ConfigPath(m.configDir, g.Interface)
		if err := os.WriteFile(path, []byte(rendered), 0600); err != nil {
			m.status[g.ID] = Status{ID:g.ID, Name:g.Name, Interface:g.Interface, Enabled:true, Running:false, LastError:err.Error(), Endpoint:g.Endpoint, LastChange:time.Now().UTC()}
			continue
		}
		_, _ = command("wg-quick", "down", path)
		out, err := command("wg-quick", "up", path)
		if err != nil {
			m.status[g.ID] = Status{ID:g.ID, Name:g.Name, Interface:g.Interface, Enabled:true, Running:false, LastError:strings.TrimSpace(string(out)), Endpoint:g.Endpoint, LastChange:time.Now().UTC()}
			continue
		}
		if err := ensurePolicyRoutes(g); err != nil {
			_, _ = command("wg-quick", "down", path)
			m.status[g.ID] = Status{ID:g.ID, Name:g.Name, Interface:g.Interface, Enabled:true, Running:false, LastError:err.Error(), Endpoint:g.Endpoint, LastChange:time.Now().UTC()}
			continue
		}
		m.status[g.ID] = Status{ID:g.ID, Name:g.Name, Interface:g.Interface, Enabled:true, Running:true, Endpoint:g.Endpoint, LastChange:time.Now().UTC()}
	}
}
