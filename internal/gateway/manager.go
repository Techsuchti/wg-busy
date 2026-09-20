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
	ID          string
	Name        string
	Interface   string
	Enabled     bool
	Running     bool
	LastError   string
	LastChange  time.Time
	Endpoint    string
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
		s = strings.TrimSpace(strings.TrimSuffix(s, ""))
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

	lines := strings.Split(raw, "
")
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
	b.WriteString("[Interface]
")
	b.WriteString("PrivateKey = " + g.PrivateKey + "
")
	b.WriteString("Address = " + g.Address + "
")
	if g.MTU != 0 {
		b.WriteString("MTU = " + strconv.Itoa(int(g.MTU)) + "
")
	}
	b.WriteString("Table = off

")
	b.WriteString("[Peer]
")
	b.WriteString("PublicKey = " + g.PublicKey + "
")
	if g.PresharedKey != "" {
		b.WriteString("PresharedKey = " + g.PresharedKey + "
")
	}
	b.WriteString("AllowedIPs = " + g.AllowedIPs + "
")
	b.WriteString("Endpoint = " + g.Endpoint + "
")
	if g.PersistentKeepalive != 0 {
		b.WriteString("PersistentKeepalive = " + strconv.Itoa(int(g.PersistentKeepalive)) + "
")
	}
	return b.String(), nil
}

func command(name string, args ...string) ([]byte, error) {
	return exec.Command(name, args...).CombinedOutput()
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
	if s.Interface != "" {
		if _, err := command("ip", "link", "show", "dev", s.Interface); err == nil {
			s.Running = true
		} else {
			s.Running = false
		}
	}
	return s
}

func (m *Manager) Reconcile(cfg models.AppConfig) {
	m.mu.Lock()
	defer m.mu.Unlock()
	desired := make(map[string]models.VPNGateway, len(cfg.VPNGateways))
	for _, g := range cfg.VPNGateways {
		desired[g.ID] = g
		if g.Interface == "" {
			g.Interface = SafeInterfaceName(g.ID)
		}
		if !g.Enabled {
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
		m.status[g.ID] = Status{ID:g.ID, Name:g.Name, Interface:g.Interface, Enabled:true, Running:true, Endpoint:g.Endpoint, LastChange:time.Now().UTC()}
	}
}
