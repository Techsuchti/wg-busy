package handlers

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	netdiscover "github.com/yix/wg-busy/internal/network"
	"github.com/yix/wg-busy/internal/models"
)

type peerNetworkDevicesData struct {
	Peer     models.Peer
	Devices  []models.PeerNetworkDevice
	Rules    map[string]string
	Gateways []models.VPNGateway
	Error    string
}

func (h *handler) buildPeerNetworkDevicesData(peerID string, devices []models.PeerNetworkDevice, errMsg string) (peerNetworkDevicesData, error) {
	var data peerNetworkDevicesData
	var found bool

	h.store.Read(func(cfg *models.AppConfig) {
		p := models.FindPeerByID(cfg.Peers, peerID)
		if p == nil {
			return
		}
		found = true
		data.Peer = *p
		data.Gateways = append([]models.VPNGateway(nil), cfg.VPNGateways...)
		data.Rules = make(map[string]string)
		for _, rule := range p.DeviceRoutingRules {
			if rule.Enabled {
				if strings.TrimSpace(rule.GatewayID) == "" {
					data.Rules[rule.DeviceIP] = "__direct__"
				} else {
					data.Rules[rule.DeviceIP] = rule.GatewayID
				}
			}
		}
	})

	if !found {
		return data, fmt.Errorf("peer not found")
	}

	if devices != nil {
		data.Devices = devices
	} else {
		data.Devices = append([]models.PeerNetworkDevice(nil), data.Peer.NetworkDevices...)
	}
	data.Error = errMsg
	return data, nil
}

// GetPeerNetworkDevices renders the device/routing section of an existing peer.
func (h *handler) GetPeerNetworkDevices(w http.ResponseWriter, r *http.Request) {
	data, err := h.buildPeerNetworkDevicesData(r.PathValue("id"), nil, "")
	if err != nil {
		writePageError(w, http.StatusNotFound, err)
		return
	}
	writePageJSON(w, http.StatusOK, "peer-network-devices", data, nil)
}

// ScanPeerNetworkDevices scans the peer networks, with an optional explicit CIDR override.
func (h *handler) ScanPeerNetworkDevices(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var peer models.Peer
	found := false
	h.store.Read(func(cfg *models.AppConfig) {
		if p := models.FindPeerByID(cfg.Peers, id); p != nil {
			peer = *p
			found = true
		}
	})
	if !found {
		writePageError(w, http.StatusNotFound, fmt.Errorf("peer not found"))
		return
	}

	devices, err := netdiscover.ScanPeer(peer, r.FormValue("network"))
	if err != nil {
		data, _ := h.buildPeerNetworkDevicesData(id, nil, err.Error())
		writePageJSON(w, http.StatusOK, "peer-network-devices", data, nil)
		return
	}

	now := time.Now().UTC()
	for i := range devices {
		devices[i].LastSeen = now
	}

	// Persist the last scan result so the device list remains available when
	// the peer dialog is opened again.
	writeErr := h.store.Write(func(cfg *models.AppConfig) error {
		p := models.FindPeerByID(cfg.Peers, id)
		if p == nil {
			return fmt.Errorf("peer not found")
		}
		p.NetworkDevices = devices
		p.UpdatedAt = now
		return nil
	})
	if writeErr != nil {
		data, _ := h.buildPeerNetworkDevicesData(id, devices, writeErr.Error())
		writePageJSON(w, http.StatusOK, "peer-network-devices", data, nil)
		return
	}

	data, _ := h.buildPeerNetworkDevicesData(id, devices, "")
	writePageJSON(w, http.StatusOK, "peer-network-devices", data, nil)
}

// UpdatePeerDeviceRoute assigns a discovered device to a VPN gateway or direct routing.
func (h *handler) UpdatePeerDeviceRoute(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	deviceIP, err := url.PathUnescape(r.PathValue("ip"))
	if err != nil {
		writePageError(w, http.StatusBadRequest, fmt.Errorf("invalid device IP"))
		return
	}
	deviceIP = strings.TrimSpace(deviceIP)
	parsed := net.ParseIP(deviceIP)
	if parsed == nil || parsed.To4() == nil {
		writePageError(w, http.StatusBadRequest, fmt.Errorf("invalid IPv4 device address"))
		return
	}

	gatewayID := strings.TrimSpace(r.FormValue("gatewayID"))
	if gatewayID != "" {
		var valid bool
		h.store.Read(func(cfg *models.AppConfig) {
			if g := models.FindVPNGatewayByID(cfg.VPNGateways, gatewayID); g != nil && g.Enabled {
				valid = true
			}
		})
		if !valid {
			writePageError(w, http.StatusBadRequest, fmt.Errorf("VPN-Gateway not found or disabled"))
			return
		}
	}

	now := time.Now().UTC()
	err = h.store.Write(func(cfg *models.AppConfig) error {
		p := models.FindPeerByID(cfg.Peers, id)
		if p == nil {
			return fmt.Errorf("peer not found")
		}
		found := false
		for i := range p.DeviceRoutingRules {
			if p.DeviceRoutingRules[i].DeviceIP != deviceIP {
				continue
			}
			found = true
			if gatewayID == "" {
				p.DeviceRoutingRules[i].GatewayID = ""
				p.DeviceRoutingRules[i].Enabled = true
			} else {
				p.DeviceRoutingRules[i].GatewayID = gatewayID
				p.DeviceRoutingRules[i].Enabled = true
			}
			break
		}
		if !found {
			p.DeviceRoutingRules = append(p.DeviceRoutingRules, models.PeerDeviceRoutingRule{
				DeviceIP: deviceIP,
				GatewayID: gatewayID,
				Enabled: true,
			})
		}
		p.UpdatedAt = now
		return nil
	})
	if err != nil {
		writePageError(w, http.StatusInternalServerError, err)
		return
	}

	data, _ := h.buildPeerNetworkDevicesData(id, nil, "")
	writePageJSON(w, http.StatusOK, "peer-network-devices", data, nil)
}
