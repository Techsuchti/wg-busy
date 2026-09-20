package handlers

import (
	"fmt"
	"html/template"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/yix/wg-busy/internal/gateway"
	"github.com/yix/wg-busy/internal/models"
)

type gatewayView struct {
	models.VPNGateway
	Running   bool
	LastError string
	Users     int
}

type gatewaysPageData struct {
	Gateways []gatewayView
}

var gatewayListTmpl = template.Must(template.New("gateways").Parse(
	"<div id=\"gateways-page\">" +
		"<div class=\"header-row\">" +
		"<div><h2>VPN Gateways</h2><small class=\"text-muted\">WireGuard-Uplinks für einzelne Peers. NordVPN und beliebige eigene WireGuard-Server können importiert werden.</small></div>" +
		"<button class=\"btn btn-primary\" hx-get=\"gateways/new\" hx-target=\"#modal-container\" hx-swap=\"innerHTML\">+ Gateway hinzufügen</button>" +
		"</div>" +
		"{{if .Gateways}}<div class=\"gateway-grid\">" +
		"{{range .Gateways}}<article class=\"gateway-card\"><header class=\"flex-row\"><div><strong>{{.Name}}</strong><div><small><code>{{.Interface}}</code> · {{.Endpoint}}</small></div></div>{{if .Running}}<span class=\"status-dot status-up\" title=\"Online\"></span>{{else}}<span class=\"status-dot status-down\" title=\"Offline\"></span>{{end}}</header>" +
		"<p><small>AllowedIPs: <code>{{.AllowedIPs}}</code></small></p><p>{{if .Enabled}}<span class=\"badge badge-ok\">Aktiviert</span>{{else}}<span class=\"badge badge-via\">Deaktiviert</span>{{end}} <span class=\"badge badge-via\">{{.Users}} Peer(s)</span></p>" +
		"{{if .LastError}}<div class=\"toast toast-error\">{{.LastError}}</div>{{end}}" +
		"<footer class=\"gateway-actions\"><button class=\"btn btn-outline secondary\" hx-put=\"gateways/{{.ID}}/toggle\" hx-target=\"#tab-content\" hx-swap=\"innerHTML\">{{if .Enabled}}Deaktivieren{{else}}Aktivieren{{end}}</button>" +
		"<button class=\"btn btn-outline-danger\" hx-delete=\"gateways/{{.ID}}\" hx-target=\"#tab-content\" hx-swap=\"innerHTML\" hx-confirm=\"Gateway wirklich löschen?\">Löschen</button></footer>" +
		"</article>{{end}}</div>{{else}}<article><p>Noch keine VPN-Gateways importiert.</p><p><small class=\"text-muted\">Lade eine WireGuard-.conf eines VPN-Anbieters oder eigenen Servers hoch.</small></p></article>{{end}}" +
		"</div>",
))

var gatewayFormTmpl = template.Must(template.New("gateway-form").Parse(
		"<dialog><article><header class=\"flex-row\"><p class=\"mb-0\"><strong>WireGuard-Gateway hinzufügen</strong></p>" +
			"<button aria-label=\"Close\" class=\"btn btn-outline secondary mb-0\" style=\"padding:.2rem .6rem;min-height:32px\" onclick=\"closeModal()\">✕</button></header>" +
			"<form method=\"post\" enctype=\"multipart/form-data\" action=\"gateways\" hx-post=\"gateways\" hx-encoding=\"multipart/form-data\" hx-target=\"#tab-content\" hx-swap=\"innerHTML\">" +
			"<label>Name *<input type=\"text\" name=\"name\" maxlength=\"64\" required placeholder=\"z. B. 🇳🇱 NordVPN NL Amsterdam\"></label>" +
			"<label>WireGuard-Konfiguration *<input type=\"file\" name=\"config\" accept=\".conf,text/plain\" required><small>Genau eine [Interface]- und [Peer]-Sektion. PreUp/PostUp und andere Shell-Hooks werden aus Sicherheitsgründen nicht ausgeführt.</small></label>" +
			"<label><input type=\"checkbox\" name=\"enabled\" checked> Gateway nach dem Import aktivieren</label>" +
			"<label><input type=\"checkbox\" name=\"autoStart\" checked> Gateway nach Container-Neustart automatisch starten</label>" +
			"<footer><button type=\"button\" class=\"btn btn-secondary\" onclick=\"closeModal()\">Abbrechen</button><button type=\"submit\" class=\"btn btn-primary\">Importieren</button></footer></form>" +
			"</article></dialog>",
))

func gatewayPageHTML(w http.ResponseWriter, data gatewaysPageData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = gatewayListTmpl.Execute(w, data)
}

func (h *handler) buildGatewayPageData() gatewaysPageData {
	var result gatewaysPageData
	if h.store == nil {
		return result
	}
	h.store.Read(func(cfg *models.AppConfig) {
		result.Gateways = make([]gatewayView, 0, len(cfg.VPNGateways))
		for _, g := range cfg.VPNGateways {
			view := gatewayView{VPNGateway: g}
			for _, p := range cfg.Peers {
				if p.VPNGatewayID == g.ID {
					view.Users++
				}
			}
			if h.gateway != nil {
				st := h.gateway.Status(g.ID)
				view.Running = st.Running
				view.LastError = st.LastError
			}
			result.Gateways = append(result.Gateways, view)
		}
	})
	return result
}

func (h *handler) GetGatewaysTab(w http.ResponseWriter, r *http.Request) {
	gatewayPageHTML(w, h.buildGatewayPageData())
}

func (h *handler) GetGatewayForm(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = gatewayFormTmpl.Execute(w, nil)
}

func (h *handler) CreateGateway(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(8 << 20); err != nil {
		http.Error(w, "Ungültige Upload-Anfrage", http.StatusBadRequest)
		return
	}

	file, _, err := r.FormFile("config")
	if err != nil {
		http.Error(w, "WireGuard-Konfigurationsdatei fehlt", http.StatusBadRequest)
		return
	}
	defer func() { _ = file.Close() }()

	raw, err := io.ReadAll(io.LimitReader(file, 512<<10))
	if err != nil {
		http.Error(w, "Konfigurationsdatei konnte nicht gelesen werden", http.StatusBadRequest)
		return
	}

	g, err := gateway.ParseConfig(string(raw))
	if err != nil {
		logRejected(r, err)
		http.Error(w, "Ungültige WireGuard-Konfiguration: "+err.Error(), http.StatusBadRequest)
		return
	}

	g.Name = strings.TrimSpace(r.FormValue("name"))
	g.Enabled = r.FormValue("enabled") == "on"
	g.AutoStart = r.FormValue("autoStart") == "on"
	g.CreatedAt = time.Now().UTC()
	g.UpdatedAt = g.CreatedAt

	id, err := newPeerID()
	if err != nil {
		http.Error(w, "Gateway-ID konnte nicht erzeugt werden", http.StatusInternalServerError)
		return
	}
	g.ID = id
	g.Interface = gateway.SafeInterfaceName(id)
	g.RoutingTableID = 0

	if g.Name == "" {
		g.Name = g.Interface
	}
	if err := g.ValidateVPNGateway(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	err = h.store.Write(func(cfg *models.AppConfig) error {
		cfg.VPNGateways = append(cfg.VPNGateways, g)
		return nil
	})
	if err != nil {
		logRejected(r, err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if h.gateway != nil && g.Enabled {
		if err := h.gateway.Start(g); err != nil {
			logRejected(r, err)
		}
	}

	gatewayPageHTML(w, h.buildGatewayPageData())
}

func (h *handler) DeleteGateway(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var old *models.VPNGateway

	err := h.store.Write(func(cfg *models.AppConfig) error {
		for i := range cfg.VPNGateways {
			if cfg.VPNGateways[i].ID == id {
				if old == nil {
					copyValue := cfg.VPNGateways[i]
					old = &copyValue
				}
				if strings.TrimSpace(cfg.VPNGateways[i].ID) != "" {
					for _, p := range cfg.Peers {
						if p.VPNGatewayID == id {
							p.VPNGatewayID = ""
						}
					}
				}
				cfg.VPNGateways = append(cfg.VPNGateways[:i], cfg.VPNGateways[i+1:]...)
				return nil
			}
		}
		return fmt.Errorf("gateway not found")
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	if old != nil && h.gateway != nil {
		_ = h.gateway.Stop(*old)
	}
	gatewayPageHTML(w, h.buildGatewayPageData())
}

func (h *handler) ToggleGateway(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var updated models.VPNGateway

	err := h.store.Write(func(cfg *models.AppConfig) error {
		g := models.FindVPNGatewayByID(cfg.VPNGateways, id)
		if g == nil {
			return fmt.Errorf("gateway not found")
		}
		g.Enabled = !g.Enabled
		g.UpdatedAt = time.Now().UTC()
		updated = *g
		return nil
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	if h.gateway != nil {
		var e error
		if updated.Enabled {
			e = h.gateway.Start(updated)
		} else {
			e = h.gateway.Stop(updated)
		}
		if e != nil {
			logRejected(r, e)
		}
	}

	gatewayPageHTML(w, h.buildGatewayPageData())
}

func (h *handler) GetGatewayStatus(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if h.gateway == nil {
		http.Error(w, "Gateway-Manager nicht verfügbar", http.StatusServiceUnavailable)
		return
	}
	st := h.gateway.Status(id)
	writePageJSON(w, http.StatusOK, "empty", st, nil)
}
