package handlers

import (
	"fmt"
	"html/template"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/yix/wg-busy/internal/models"
)

type systemCheck struct {
	Name   string
	Status string
	Detail string
	OK     bool
}

type systemPeerView struct {
	Name       string
	Address    string
	Gateway    string
	Enabled    bool
	LastSeen   string
	TransferRX string
	TransferTX string
}

type systemGatewayView struct {
	Name            string
	Interface       string
	Endpoint        string
	Enabled         bool
	Running         bool
	Handshake       string
	TransferRX      string
	TransferTX      string
	RoutingTableID  uint
	PeerCount       int
	LastError       string
}

type systemPageData struct {
	Version       string
	GoVersion     string
	OS            string
	Arch          string
	Uptime        string
	WireGuardUp   bool
	PeerCount     int
	ActivePeers   int
	GatewayCount  int
	RunningGateways int
	IPv6Gateways  int
	Checks        []systemCheck
	Peers         []systemPeerView
	Gateways      []systemGatewayView
	IPRules       string
	Routes        string
}

var systemPageTmpl = template.Must(template.New("system").Funcs(template.FuncMap{"ifClass": ifClass}).Parse(`
<div id="system-page">
	<div class="header-row">
		<div>
			<h2>System &amp; Diagnose</h2>
			<small class="text-muted">Betriebsstatus, Routing, VPN-Gateways und Sicherheitsprüfungen.</small>
		</div>
		<button class="btn btn-outline secondary" hx-get="system" hx-target="#tab-content" hx-swap="innerHTML">↻ Aktualisieren</button>
	</div>

	<div class="grid system-stat-grid">
		<article class="stat-card"><header><strong>Version</strong></header><div>{{Version}}</div></article>
		<article class="stat-card"><header><strong>WireGuard</strong></header><div>{{if WireGuardUp}}<span class="status-dot status-up"></span> Online{{else}}<span class="status-dot status-down"></span> Offline{{end}}</div></article>
		<article class="stat-card"><header><strong>Peers</strong></header><div>{{ActivePeers}} / {{PeerCount}} aktiv</div></article>
		<article class="stat-card"><header><strong>VPN-Gateways</strong></header><div>{{RunningGateways}} / {{GatewayCount}} aktiv</div></article>
	</div>

	<section class="config-section">
		<h3>Systeminformationen</h3>
		<div class="table-responsive">
			<table role="grid">
				<tbody>
					<tr><th>Version</th><td><code>{{Version}}</code></td></tr>
					<tr><th>Go Runtime</th><td><code>{{GoVersion}}</code></td></tr>
					<tr><th>Plattform</th><td><code>{{OS}} / {{Arch}}</code></td></tr>
					<tr><th>WireGuard Uptime</th><td>{{Uptime}}</td></tr>
					<tr><th>IPv6 Full-Tunnel Gateways</th><td>{{IPv6Gateways}}</td></tr>
				</tbody>
			</table>
		</div>
	</section>

	<section class="config-section">
		<h3>Sicherheitsprüfungen</h3>
		<div class="system-check-grid">
			{{#each Checks}}
			<div class="system-check {{ifClass OK "check-ok" "check-warn"}}">
				<div><span class="status-dot {{ifClass OK "status-up" "status-down"}}"></span><strong>{{Name}}</strong></div>
				<small>{{Status}} · {{Detail}}</small>
			</div>
			{{/each}}
		</div>
	</section>

	<section class="config-section">
		<h3>VPN-Gateways</h3>
		{{if Gateways}}
		<div class="gateway-grid">
			{{#each Gateways}}
			<article class="gateway-card">
				<header class="flex-row">
					<div><strong>{{Name}}</strong><div><small><code>{{Interface}}</code> · {{Endpoint}}</small></div></div>
					{{if Running}}<span class="status-dot status-up" title="Online"></span>{{else}}<span class="status-dot status-down" title="Offline"></span>{{/if}}
				</header>
				<div class="system-metrics">
					<span>Handshake: <strong>{{Handshake}}</strong></span>
					<span>RX: <strong>{{TransferRX}}</strong></span>
					<span>TX: <strong>{{TransferTX}}</strong></span>
					<span>Routing: <strong>{{RoutingTableID}}</strong></span>
				</div>
				{{if LastError}}<div class="toast toast-error">{{LastError}}</div>{{/if}}
			</article>
			{{/each}}
		</div>
		{{else}}<p class="text-muted">Keine VPN-Gateways konfiguriert.</p>{{/if}}
	</section>

	<section class="config-section">
		<h3>Peer → Gateway Routing</h3>
		{{if Peers}}
		<div class="table-responsive">
			<table role="grid">
				<thead><tr><th>Peer</th><th>Adresse</th><th>Gateway</th><th>Status</th><th>Letzter Handshake</th><th>Traffic</th></tr></thead>
				<tbody>
				{{#each Peers}}
					<tr>
						<td><strong>{{Name}}</strong></td>
						<td><code>{{Address}}</code></td>
						<td>{{Gateway}}</td>
						<td>{{if Enabled}}<span class="badge badge-ok">Aktiv</span>{{else}}<span class="badge badge-via">Deaktiviert</span>{{/if}}</td>
						<td>{{LastSeen}}</td>
						<td>{{TransferRX}} ↓ / {{TransferTX}} ↑</td>
					</tr>
				{{/each}}
				</tbody>
			</table>
		</div>
		{{else}}<p class="text-muted">Keine Peers vorhanden.</p>{{/if}}
	</section>

	<section class="config-section">
		<h3>Policy Routing</h3>
		<details>
			<summary><strong>ip rule</strong></summary>
			<pre class="diagnostic-output">{{IPRules}}</pre>
		</details>
		<details>
			<summary><strong>VPN-Gateway Routing Tables</strong></summary>
			<pre class="diagnostic-output">{{Routes}}</pre>
		</details>
	</section>

	<section class="config-section">
		<h3>Diagnose</h3>
		<p class="text-muted">Diese Ansicht enthält bewusst keine privaten WireGuard-Schlüssel oder Preshared Keys.</p>
		<button class="btn btn-outline secondary" onclick="copyText(document.getElementById('diagnostic-summary').innerText, this)">Diagnose kopieren</button>
		<pre id="diagnostic-summary" class="diagnostic-output">wg-busy {{Version}}
Platform: {{OS}}/{{Arch}}
WireGuard: {{if WireGuardUp}}UP{{else}}DOWN{{/if}}
Peers: {{ActivePeers}}/{{PeerCount}}
Gateways: {{RunningGateways}}/{{GatewayCount}}
IPv6 gateways: {{IPv6Gateways}}

{{IPRules}}

{{Routes}}</pre>
	</section>
</div>
`))

func ifClass(ok bool, yes, no string) string {
	if ok {
		return yes
	}
	return no
}

func formatSystemBytes(v int64) string {
	if v < 1024 {
		return fmt.Sprintf("%d B", v)
	}
	const unit = 1024
	div, exp := int64(unit), 0
	for v >= div*unit && exp < 5 {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(v)/float64(div), "KMGTPE"[exp])
}

func formatHandshake(t time.Time) string {
	if t.IsZero() {
		return "nie"
	}
	age := time.Since(t)
	if age < 0 {
		age = 0
	}
	switch {
	case age < time.Minute:
		return fmt.Sprintf("vor %d s", int(age.Seconds()))
	case age < time.Hour:
		return fmt.Sprintf("vor %d min", int(age.Minutes()))
	case age < 24*time.Hour:
		return fmt.Sprintf("vor %d h", int(age.Hours()))
	default:
		return t.Local().Format("02.01.2006 15:04")
	}
}

func commandOutput(name string, args ...string) string {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return strings.TrimSpace(string(out)) + " (command error)"
	}
	return strings.TrimSpace(string(out))
}

func fileIsPrivate(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.Mode().Perm()&0077 == 0
}

func (h *handler) GetSystemTab(w http.ResponseWriter, r *http.Request) {
	var data systemPageData
	data.Version = "dev"
	data.GoVersion = runtime.Version()
	data.OS = runtime.GOOS
	data.Arch = runtime.GOARCH

	if h.stats != nil {
		data.WireGuardUp = h.stats.IsUp()
		data.Uptime = h.stats.Uptime().Round(time.Second).String()
	}

	h.store.Read(func(cfg *models.AppConfig) {
		data.PeerCount = len(cfg.Peers)
		for _, p := range cfg.Peers {
			gatewayName := "Kein VPN-Gateway"
			if g := models.FindVPNGatewayByID(cfg.VPNGateways, p.VPNGatewayID); g != nil {
				gatewayName = g.Name
			}
			if !p.LastSeen.IsZero() {
				data.ActivePeers++
			}
			data.Peers = append(data.Peers, systemPeerView{
				Name: p.Name, Address: p.AllowedIPs, Gateway: gatewayName,
				Enabled: p.Enabled, LastSeen: formatHandshake(p.LastSeen),
				TransferRX: formatSystemBytes(p.TransferRx), TransferTX: formatSystemBytes(p.TransferTx),
			})
		}
		data.GatewayCount = len(cfg.VPNGateways)
		for _, g := range cfg.VPNGateways {
			if strings.Contains(g.AllowedIPs, "::/0") {
				data.IPv6Gateways++
			}
			view := systemGatewayView{
				Name: g.Name, Interface: g.Interface, Endpoint: g.Endpoint,
				Enabled: g.Enabled, RoutingTableID: g.RoutingTableID,
			}
			if h.gateway != nil {
				st := h.gateway.Status(g.ID)
				view.Running = st.Running
				view.Handshake = formatHandshake(st.LatestHandshake)
				view.TransferRX = formatSystemBytes(st.ReceiveBytes)
				view.TransferTX = formatSystemBytes(st.TransmitBytes)
				view.PeerCount = st.PeerCount
				view.LastError = st.LastError
				if st.Running {
					data.RunningGateways++
				}
			}
			data.Gateways = append(data.Gateways, view)
		}

		configPath := h.store.ConfigPath()
		wgPath := h.store.WGConfigPath()
		authOK := cfg.Server.RequirePasskey && len(cfg.Server.Passkeys) > 0
		data.Checks = append(data.Checks, systemCheck{
			Name: "Admin-Passkey", OK: authOK,
			Status: map[bool]string{true: "OK", false: "WARN"}[authOK],
			Detail: map[bool]string{true: "WebAuthn/FIDO2 ist aktiviert", false: "Passkey-Schutz ist nicht vollständig aktiviert"}[authOK],
		})
		configOK := fileIsPrivate(configPath)
		data.Checks = append(data.Checks, systemCheck{
			Name: "Config-Datei", OK: configOK,
			Status: map[bool]string{true: "OK", false: "WARN"}[configOK],
			Detail: configPath,
		})
		wgOK := fileIsPrivate(wgPath)
		data.Checks = append(data.Checks, systemCheck{
			Name: "WireGuard-Config", OK: wgOK,
			Status: map[bool]string{true: "OK", false: "WARN"}[wgOK],
			Detail: wgPath,
		})
	})

	data.IPRules = commandOutput("ip", "rule")
	if data.IPRules == "" {
		data.IPRules = "Keine Policy-Routing-Regeln gefunden."
	}
	var routeLines []string
	h.store.Read(func(cfg *models.AppConfig) {
		for _, g := range cfg.VPNGateways {
			if g.RoutingTableID == 0 {
				continue
			}
			routeLines = append(routeLines, fmt.Sprintf("table %d (%s):\n%s", g.RoutingTableID, g.Name,
				commandOutput("ip", "route", "show", "table", fmt.Sprint(g.RoutingTableID))))
			if strings.Contains(g.AllowedIPs, "::/0") {
				routeLines = append(routeLines, fmt.Sprintf("table %d IPv6:\n%s", g.RoutingTableID,
					commandOutput("ip", "-6", "route", "show", "table", fmt.Sprint(g.RoutingTableID))))
			}
		}
	})
	data.Routes = strings.Join(routeLines, "\n\n")
	if data.Routes == "" {
		data.Routes = "Keine VPN-Gateway-Routingtabellen gefunden."
	}

	// Version is injected into the handler at router construction time through
	// a private field added to the handler. Keep a safe fallback for old callers.
	if h.version != "" {
		data.Version = h.version
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := systemPageTmpl.Execute(w, data); err != nil {
		http.Error(w, "rendering system page failed", http.StatusInternalServerError)
	}
}
