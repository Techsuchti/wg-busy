package handlers

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/yix/wg-busy/internal/ipam"
	"github.com/yix/wg-busy/internal/models"
	"github.com/yix/wg-busy/internal/wireguard"
)

type quickPeerData struct {
	Peer models.Peer
}

type gatewayAssignmentPeer struct {
	ID            string
	Name          string
	AllowedIPs    string
	VPNGatewayID  string
	Enabled       bool
	GatewayName   string
	GatewayOnline bool
}

type gatewayAssignmentsData struct {
	Peers    []gatewayAssignmentPeer
	Gateways []models.VPNGateway
}

func (h *handler) GetQuickPeerForm(w http.ResponseWriter, r *http.Request) {
	writePageJSON(w, http.StatusOK, "quick-peer-form", struct{}{}, nil)
}

func (h *handler) CreateQuickPeer(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writePageError(w, http.StatusBadRequest, fmt.Errorf("bad request"))
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		writePageJSON(w, http.StatusUnprocessableEntity, "quick-peer-form", struct{ Error string }{Error: "Name ist erforderlich."}, nil)
		return
	}
	if len(name) > 64 {
		writePageJSON(w, http.StatusUnprocessableEntity, "quick-peer-form", struct{ Error string }{Error: "Name darf maximal 64 Zeichen enthalten."}, nil)
		return
	}

	priv, pub, err := wireguard.GenerateKeyPair()
	if err != nil {
		writePageError(w, http.StatusInternalServerError, fmt.Errorf("key generation failed: %w", err))
		return
	}
	psk, err := wireguard.GeneratePresharedKey()
	if err != nil {
		writePageError(w, http.StatusInternalServerError, fmt.Errorf("PSK generation failed: %w", err))
		return
	}
	id, err := newPeerID()
	if err != nil {
		writePageError(w, http.StatusInternalServerError, fmt.Errorf("ID generation failed: %w", err))
		return
	}

	peer := models.Peer{
		ID: id, Name: name, PrivateKey: priv, PublicKey: pub, PresharedKey: psk,
		ClientAllowedIPs: "0.0.0.0/0, ::/0", PersistentKeepalive: 25,
		Enabled: true, CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
	}

	err = h.store.Write(func(cfg *models.AppConfig) error {
		used := make([]string, len(cfg.Peers))
		for i, p := range cfg.Peers { used[i] = p.AllowedIPs }
		ip, err := ipam.NextAvailableIP(cfg.Server.Address, used)
		if err != nil { return fmt.Errorf("auto-assign IP: %w", err) }
		peer.AllowedIPs = ip
		if errs := peer.Validate(models.GatewayNets(cfg.Server.Address, h.ztGatewayNets())); len(errs) > 0 {
			return errs
		}
		cfg.Peers = append(cfg.Peers, peer)
		return nil
	})
	if err != nil {
		logRejected(r, err)
		if warning, ok := applyWarning(err); ok {
			h.listPeersOOB(w, r, &warning)
			return
		}
		writePageJSON(w, http.StatusUnprocessableEntity, "quick-peer-form", struct{ Error string }{Error: err.Error()}, nil)
		return
	}

	data := struct {
		Peer quickPeerData
	}{Peer: quickPeerData{Peer: peer}}
	writePageJSON(w, http.StatusOK, "quick-peer-created", data, nil)
}

func (h *handler) GetGatewayAssignments(w http.ResponseWriter, r *http.Request) {
	writePageJSON(w, http.StatusOK, "gateway-assignments", h.buildGatewayAssignmentsData(), nil)
}

func (h *handler) buildGatewayAssignmentsData() gatewayAssignmentsData {
	var data gatewayAssignmentsData
	h.store.Read(func(cfg *models.AppConfig) {
		data.Gateways = append([]models.VPNGateway(nil), cfg.VPNGateways...)
		for _, p := range cfg.Peers {
			row := gatewayAssignmentPeer{ID: p.ID, Name: p.Name, AllowedIPs: p.AllowedIPs, VPNGatewayID: p.VPNGatewayID, Enabled: p.Enabled}
			if g := models.FindVPNGatewayByID(cfg.VPNGateways, p.VPNGatewayID); g != nil {
				row.GatewayName = g.Name
				if h.gateway != nil {
					row.GatewayOnline = h.gateway.Status(g.ID).Running
				}
			}
			data.Peers = append(data.Peers, row)
		}
	})
	sort.Slice(data.Peers, func(i, j int) bool { return strings.ToLower(data.Peers[i].Name) < strings.ToLower(data.Peers[j].Name) })
	return data
}

func (h *handler) AssignPeerGateway(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := r.ParseForm(); err != nil {
		writePageError(w, http.StatusBadRequest, fmt.Errorf("bad request"))
		return
	}
	gatewayID := strings.TrimSpace(r.FormValue("vpnGatewayID"))

	err := h.store.Write(func(cfg *models.AppConfig) error {
		p := models.FindPeerByID(cfg.Peers, id)
		if p == nil { return fmt.Errorf("peer not found") }
		if gatewayID != "" && models.FindVPNGatewayByID(cfg.VPNGateways, gatewayID) == nil {
			return fmt.Errorf("gateway not found")
		}
		p.VPNGatewayID = gatewayID
		p.UpdatedAt = time.Now().UTC()
		return nil
	})
	if err != nil {
		logRejected(r, err)
		if warning, ok := applyWarning(err); ok {
			writePageJSON(w, http.StatusOK, "gateway-assignments", h.buildGatewayAssignmentsData(), &warning)
			return
		}
		writePageError(w, http.StatusBadRequest, err)
		return
	}
	writePageJSON(w, http.StatusOK, "gateway-assignments", h.buildGatewayAssignmentsData(), nil)
}
