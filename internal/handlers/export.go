package handlers

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/yix/wg-busy/internal/models"
	"github.com/yix/wg-busy/internal/routing"
	"github.com/yix/wg-busy/internal/wireguard"
)

// DownloadClientConfig handles GET /api/peers/{id}/config.
func (h *handler) DownloadClientConfig(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	var content string
	var filename string
	var genErr error

	h.store.Read(func(cfg *models.AppConfig) {
		peer := models.FindPeerByID(cfg.Peers, id)
		if peer == nil {
			genErr = fmt.Errorf("peer not found")
			return
		}

		endpoint := clientEndpointFromRequest(r, cfg.Server.ListenPort)
		content, genErr = wireguard.RenderClientConfigWithEndpoint(cfg.Server, *peer, endpoint)
		if genErr != nil {
			return
		}

		// Sanitize name for filename.
		name := strings.ReplaceAll(peer.Name, " ", "-")
		name = strings.Map(func(r rune) rune {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
				return r
			}
			return -1
		}, name)
		if name == "" {
			name = peer.ID
		}
		filename = name + ".conf"
	})

	if genErr != nil {
		http.Error(w, genErr.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	_, _ = w.Write([]byte(content))
}

// DownloadServerConfig handles GET /api/server/config.
func (h *handler) DownloadServerConfig(w http.ResponseWriter, r *http.Request) {
	var content string
	var genErr error

	h.store.Read(func(cfg *models.AppConfig) {
		gateways := models.GatewayNets(cfg.Server.Address, h.ztGatewayNets())
		postUpCmds := routing.GeneratePostUpCommands(*cfg, gateways)
		postDownCmds := routing.GeneratePostDownCommands(*cfg, gateways)
		content, genErr = wireguard.RenderServerConfig(*cfg, postUpCmds, postDownCmds)
	})

	if genErr != nil {
		http.Error(w, genErr.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="wg0.conf"`)
	_, _ = w.Write([]byte(content))
}

// ApplyConfig handles POST /api/server/apply.
func (h *handler) ApplyConfig(w http.ResponseWriter, r *http.Request) {
	// wg0.conf is already on disk (written on every save).
	// Just restart the interface.
	if err := wireguard.RestartWGConfig(h.store.WGConfigPath()); err != nil {
		msg := fmt.Sprintf("Failed to apply config: %v", err)
		toast := toastData{Kind: "error", Message: msg}
		writePageJSON(w, http.StatusOK, "empty", struct{}{}, &toast)
		return
	}
	h.store.MarkWireGuardRestarted()
	if err := errors.Join(h.store.ReapplyRouting(), h.store.ReapplyBGP()); err != nil {
		toast := toastData{Kind: "error", Message: "WireGuard restarted, but dependent services did not fully apply: " + err.Error()}
		writePageJSON(w, http.StatusOK, "empty", struct{}{}, &toast)
		return
	}

	// Reset uptime tracking on successful restart.
	if h.stats != nil {
		h.stats.SetStartedAt(time.Now())
	}

	toast := toastData{Kind: "success", Message: "WireGuard configuration applied successfully."}
	writePageJSON(w, http.StatusOK, "empty", struct{}{}, &toast)
}

// clientEndpointFromRequest derives a WireGuard endpoint from the address used
// to access the web UI. An explicitly configured Server.Endpoint always wins.
func clientEndpointFromRequest(r *http.Request, listenPort uint16) string {
	if r == nil {
		return ""
	}

	host := strings.TrimSpace(r.Header.Get("X-Forwarded-Host"))
	if host == "" {
		host = strings.TrimSpace(r.Host)
	}
	if host == "" {
		return ""
	}

	// Remove the web UI port while preserving IPv6 literals.
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	} else {
		host = strings.Trim(host, "[]")
	}
	if host == "" {
		return ""
	}

	if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
		return fmt.Sprintf("[%s]:%d", host, listenPort)
	}
	return fmt.Sprintf("%s:%d", host, listenPort)
}
