package handlers

import (
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"mime"
	"os"
	"path/filepath"
	"sync"
	"time"
	"net/http"
	"strconv"
	"strings"
	"net"

	"github.com/yix/wg-busy/internal/gateway"

	"github.com/yix/wg-busy/internal/auth"
	"github.com/yix/wg-busy/internal/config"
	"github.com/yix/wg-busy/internal/models"
	"github.com/yix/wg-busy/internal/wgstats"
	"github.com/yix/wg-busy/internal/zerotier"
)

func applyError(err error) (*config.ApplyError, bool) {
	var result *config.ApplyError
	ok := errors.As(err, &result)
	return result, ok
}

func applyWarning(err error) (toastData, bool) {
	if _, ok := applyError(err); !ok {
		return toastData{}, false
	}
	return toastData{Kind: "error", Message: err.Error()}, true
}

type toastData struct {
	Kind    string
	Message string
}

type pageResponse struct {
	Template string
	Data     any
	Toast    *toastData `json:",omitempty"`
}

func writePageJSON(w http.ResponseWriter, status int, templateName string, data any, toast *toastData) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(pageResponse{Template: templateName, Data: data, Toast: toast})
}

func writePageError(w http.ResponseWriter, status int, err error) {
	writePageJSON(w, status, "empty", struct{ Error string }{Error: err.Error()}, nil)
}

type handler struct {
	store    *config.Store
	stats    *wgstats.Collector
	zt       *zerotier.Supervisor
	gateway  *gateway.Manager
	sessions *auth.SessionManager
	webauthn *auth.WebAuthnService
	version  string
	auditMu  sync.Mutex
	auditPath string
}

// ztGatewayNets returns the ZeroTier on-link networks, or nil when ZeroTier is
// not running. It reads only the supervisor's cached snapshot, so it is safe to
// call while the config store lock is held.
func (h *handler) ztGatewayNets() []models.GatewayNet {
	if h.zt == nil {
		return nil
	}
	return h.zt.GatewayNets()
}

// logRejected records why a user action was rejected. The middleware logs that a
// request failed; this logs what was wrong with it.
func logRejected(r *http.Request, err error) {
	log.Printf("rejected %s %s from %s: %v", r.Method, r.URL.Path, r.RemoteAddr, err)
}

// statusRecorder captures the response status, and the body of plain-text error
// responses (everything http.Error writes), so the middleware can log both.
type statusRecorder struct {
	http.ResponseWriter
	status int
	detail string
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if s.status >= 400 && s.detail == "" {
		contentType := s.Header().Get("Content-Type")
		if strings.HasPrefix(contentType, "text/plain") {
			s.detail = strings.TrimSpace(string(b))
		} else if strings.HasPrefix(contentType, "application/json") {
			var response struct {
				Data struct{ Error string }
			}
			if json.Unmarshal(b, &response) == nil {
				s.detail = response.Data.Error
			}
		}
	}
	return s.ResponseWriter.Write(b)
}

// logErrors logs every request that ends in a 4xx or 5xx, so no failed user
// action is invisible in the app log.
func logErrors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		if rec.status >= 400 {
			msg := fmt.Sprintf("%d %s %s from %s", rec.status, r.Method, r.URL.Path, r.RemoteAddr)
			if rec.detail != "" {
				msg += ": " + rec.detail
			}
			log.Print(msg)
		}
	})
}

type gzipResponseWriter struct {
	http.ResponseWriter
	writer      *gzip.Writer
	allow       bool
	wroteHeader bool
}

func (w *gzipResponseWriter) WriteHeader(status int) {
	if w.wroteHeader {
		return
	}
	w.wroteHeader = true
	if w.allow && status != http.StatusNoContent && status != http.StatusNotModified && isCompressible(w.Header().Get("Content-Type")) {
		w.Header().Del("Content-Length")
		w.Header().Set("Content-Encoding", "gzip")
		w.writer = gzip.NewWriter(w.ResponseWriter)
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *gzipResponseWriter) Write(body []byte) (int, error) {
	if !w.wroteHeader {
		if w.Header().Get("Content-Type") == "" {
			w.Header().Set("Content-Type", http.DetectContentType(body))
		}
		w.WriteHeader(http.StatusOK)
	}
	if w.writer != nil {
		return w.writer.Write(body)
	}
	return w.ResponseWriter.Write(body)
}

func (w *gzipResponseWriter) close() {
	if w.writer != nil {
		_ = w.writer.Close()
	}
}

func gzipResponses(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Vary", "Accept-Encoding")
		writer := &gzipResponseWriter{
			ResponseWriter: w,
			allow:          r.Method != http.MethodHead && r.Header.Get("Range") == "" && acceptsGzip(r.Header.Values("Accept-Encoding")),
		}
		defer writer.close()
		next.ServeHTTP(writer, r)
	})
}

func acceptsGzip(values []string) bool {
	gzipQuality, wildcardQuality := -1.0, -1.0
	for _, value := range values {
		for _, item := range strings.Split(value, ",") {
			name, params, err := mime.ParseMediaType(strings.TrimSpace(item))
			if err != nil {
				continue
			}
			quality := 1.0
			if raw, ok := params["q"]; ok {
				quality, err = strconv.ParseFloat(raw, 64)
				if err != nil {
					continue
				}
			}
			switch {
			case strings.EqualFold(name, "gzip"):
				gzipQuality = quality
			case name == "*":
				wildcardQuality = quality
			}
		}
	}
	if gzipQuality >= 0 {
		return gzipQuality > 0
	}
	return wildcardQuality > 0
}

func isCompressible(contentType string) bool {
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return false
	}
	return strings.HasPrefix(mediaType, "text/") || mediaType == "application/json" || mediaType == "application/javascript" || mediaType == "application/xml" || mediaType == "image/svg+xml"
}

// auditMutation records successful state-changing requests without logging request bodies or secrets.
func (h *handler) auditMutation(r *http.Request, status int) {
	if status >= 400 || (r.Method != http.MethodPost && r.Method != http.MethodPut && r.Method != http.MethodDelete && r.Method != http.MethodPatch) {
		return
	}
	h.auditMu.Lock()
	defer h.auditMu.Unlock()
	if h.auditPath == "" {
		return
	}
	if err := os.MkdirAll(filepath.Dir(h.auditPath), 0700); err != nil {
		return
	}
	f, err := os.OpenFile(h.auditPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return
	}
	defer f.Close()
	remote := r.RemoteAddr
	if host, _, err := net.SplitHostPort(remote); err == nil {
		remote = host
	}
	_, _ = fmt.Fprintf(f, "%s %s %s from %s status=%d\\n", time.Now().UTC().Format(time.RFC3339), r.Method, r.URL.Path, remote, status)
}

// auditMiddleware records successful state-changing requests after authentication.
func (h *handler) auditMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		h.auditMutation(r, rec.status)
	})
}

// requireAuth checks whether passkey authentication is enforced and valid.
func (h *handler) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var requirePasskey bool
		var hasPasskeys bool
		if h.store != nil {
			h.store.Read(func(cfg *models.AppConfig) {
				requirePasskey = cfg.Server.RequirePasskey
				hasPasskeys = len(cfg.Server.Passkeys) > 0
			})
		}

		if !requirePasskey || !hasPasskeys {
			next.ServeHTTP(w, r)
			return
		}

		path := r.URL.Path
		if path == "/" ||
			path == "/version" ||
			path == "/favicon.ico" ||
			strings.HasPrefix(path, "/favicon-options/") ||
			path == "/index.css" ||
			path == "/templates.html" ||
			path == "/api/auth/status" ||
			path == "/api/auth/login/begin" ||
			path == "/api/auth/login/finish" ||
			path == "/api/auth/logout" {
			next.ServeHTTP(w, r)
			return
		}

		if h.sessions.ValidateSession(r) {
			next.ServeHTTP(w, r)
			return
		}

		// Unauthenticated request
		if r.Header.Get("HX-Request") == "true" {
			writePageJSON(w, http.StatusUnauthorized, "login-card", struct{}{}, nil)
			return
		}
		if strings.HasPrefix(path, "/api/") {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		http.Redirect(w, r, "/", http.StatusSeeOther)
	})
}

// NewRouter creates the HTTP mux with all routes registered.
func NewRouter(store *config.Store, webFS fs.FS, stats *wgstats.Collector, zt *zerotier.Supervisor, gatewayManager *gateway.Manager, version string) http.Handler {
	challenges := auth.NewChallengeStore()
	sessions := auth.NewSessionManager()
	webauthn := auth.NewWebAuthnService(challenges)

	h := &handler{
		store:    store,
		stats:    stats,
		zt:       zt,
		gateway:  gatewayManager,
		sessions: sessions,
		webauthn: webauthn,
		version:  version,
		auditPath: filepath.Join(filepath.Dir(store.ConfigPath()), "audit.log"),
	}

	mux := http.NewServeMux()

	// Static files (index.html).
	mux.Handle("GET /", http.FileServerFS(webFS))
	mux.HandleFunc("GET /version", func(w http.ResponseWriter, _ *http.Request) {
		writePageJSON(w, http.StatusOK, "version", struct{ Version string }{Version: version}, nil)
	})

	// Stats bar fragment (includes active-tab OOB stats selected by ?kind=).
	mux.HandleFunc("GET /stats", h.GetCombinedStats)

	// Auth endpoints.
	mux.HandleFunc("GET /api/auth/status", h.GetAuthStatus)
	mux.HandleFunc("POST /api/auth/login/begin", h.BeginLogin)
	mux.HandleFunc("POST /api/auth/login/finish", h.FinishLogin)
	mux.HandleFunc("POST /api/auth/logout", h.Logout)
	mux.HandleFunc("POST /api/auth/passkeys/begin", h.BeginPasskeyRegistration)
	mux.HandleFunc("POST /api/auth/passkeys/finish", h.FinishPasskeyRegistration)
	mux.HandleFunc("DELETE /api/auth/passkeys/{id}", h.DeletePasskey)

	// Peer fragment endpoints.
	mux.HandleFunc("GET /peers/quick", h.GetQuickPeerForm)
	mux.HandleFunc("POST /peers/quick", h.CreateQuickPeer)
	mux.HandleFunc("GET /peers", h.ListPeers)
	mux.HandleFunc("GET /peers/new", h.GetPeerForm)
	mux.HandleFunc("GET /peers/{id}/edit", h.GetPeerForm)
	mux.HandleFunc("POST /peers", h.CreatePeer)
	mux.HandleFunc("PUT /peers/{id}", h.UpdatePeer)
	mux.HandleFunc("DELETE /peers/{id}", h.DeletePeer)
	mux.HandleFunc("PUT /peers/{id}/toggle", h.TogglePeer)

	// QR code modal (HTML dialog).
	mux.HandleFunc("GET /peers/{id}/qr", h.QRCodeModal)

	// Server config fragment endpoints.
	mux.HandleFunc("GET /server", h.GetServerConfig)
	mux.HandleFunc("PUT /server", h.UpdateServerConfig)
	mux.HandleFunc("GET /server/show", h.ShowWGStatus)

	// BGP tab; live data is refreshed through the active-tab /stats request.
	mux.HandleFunc("GET /bgp/stats", h.GetBGPStatsTab)
	mux.HandleFunc("PUT /bgp/server", h.UpdateBGPServerConfig)

	// Custom (non-WireGuard) BGP peer fragment endpoints.
	mux.HandleFunc("GET /bgp/peers/new", h.GetBGPPeerForm)
	mux.HandleFunc("GET /bgp/peers/{id}/edit", h.GetBGPPeerForm)
	mux.HandleFunc("POST /bgp/peers", h.CreateBGPPeer)
	mux.HandleFunc("PUT /bgp/peers/{id}", h.UpdateBGPPeer)
	mux.HandleFunc("DELETE /bgp/peers/{id}", h.DeleteBGPPeer)

	// System / diagnostics endpoint.
	mux.HandleFunc("GET /system", h.GetSystemTab)

	// VPN gateway endpoints.
	mux.HandleFunc("GET /gateway-assignments", h.GetGatewayAssignments)
	mux.HandleFunc("PUT /gateway-assignments/{id}", h.AssignPeerGateway)
	mux.HandleFunc("GET /gateways", h.GetGatewaysTab)
	mux.HandleFunc("GET /gateways/new", h.GetGatewayForm)
	mux.HandleFunc("POST /gateways", h.CreateGateway)
	mux.HandleFunc("DELETE /gateways/{id}", h.DeleteGateway)
	mux.HandleFunc("PUT /gateways/{id}/toggle", h.ToggleGateway)
	mux.HandleFunc("GET /gateways/{id}/status", h.GetGatewayStatus)

	// ZeroTier fragment endpoints.
	mux.HandleFunc("GET /zerotier", h.GetZeroTierTab)
	mux.HandleFunc("GET /zerotier/status", h.GetZeroTierStatus)
	mux.HandleFunc("PUT /zerotier", h.UpdateZeroTier)
	mux.HandleFunc("POST /zerotier/networks", h.JoinZeroTierNetwork)
	mux.HandleFunc("DELETE /zerotier/networks/{id}", h.LeaveZeroTierNetwork)

	// API endpoints.
	mux.HandleFunc("GET /api/peers/{id}/config", h.DownloadClientConfig)
	mux.HandleFunc("GET /api/peers/{id}/qr", h.QRCode)
	mux.HandleFunc("GET /api/server/config", h.DownloadServerConfig)
	mux.HandleFunc("POST /api/server/apply", h.ApplyConfig)
	mux.HandleFunc("POST /api/peers/{id}/regenerate-keys", h.RegeneratePeerKeys)
	mux.HandleFunc("POST /api/zerotier/restart", h.RestartZeroTier)

	return gzipResponses(logErrors(h.auditMiddleware(h.requireAuth(mux))))
}
