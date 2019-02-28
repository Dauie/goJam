package main

import (
	"errors"
	"log"
	"net"
	"strings"

	"github.com/dauie/go-netlink/nl80211"
	"github.com/google/gopacket/layers"
	"github.com/mdlayher/genetlink"
	"github.com/mdlayher/netlink"
)

type Client		struct {
	tap			layers.RadioTap
	dot			layers.Dot11
	hwaddr		net.HardwareAddr
}

type Ap			struct {
	hwaddr		net.HardwareAddr
	ssid		string
	tap			layers.RadioTap
	dot			layers.Dot11
	clients		map[string]*Client
}

func	(s *Ap)	AddClient(client *Client) {

	if s.clients == nil {
		s.clients = make(map[string]*Client)
	}
	s.clients[client.hwaddr.String()] = client
}

func	(s *Ap)	DelClient(addr net.HardwareAddr) {

	if s.clients == nil {
		return
	}
	delete(s.clients, addr.String())
}

func	(s *Ap)	GetClient(addr net.HardwareAddr) (*Client, bool) {

	if s.clients != nil {
		client, ok := s.clients[addr.String()]
		return client, ok
	}
	return nil, false
}

//this is kinda hacks, but genetlink.AttributeDecoder is having issues with BSS_IEs
// or maybe im just an idiot
func	(s *Ap)	getSSIDFromBSSIE(b []byte) error {

	ssidLen := uint(b[1])
	if ssidLen != 0 {
		s.ssid = strings.TrimSpace(string(b[2:ssidLen + 2]))
	} else {
		s.ssid = NoSSID
	}
	return nil
}

func	(s *Ap)	DecodeBSS(b []byte) error {

	ad, err := netlink.NewAttributeDecoder(b)
	if err != nil {
		log.Panicln("netlink.NewAttributeDecoder() " + err.Error())
	}
	for ad.Next() {
		switch ad.Type() {
		case nl80211.BSS_BSSID:
			s.hwaddr = ad.Bytes()
			break
		case nl80211.BSS_INFORMATION_ELEMENTS:
			ad.Do(s.getSSIDFromBSSIE)
			break
		default:
			break
		}
	}
	return nil
}

func	decodeScanResults(msgs []genetlink.Message) ([]Ap, error) {

	var ap	Ap
	var	aps	[]Ap

	for _, v := range msgs {
		ad, err := netlink.NewAttributeDecoder(v.Data)
		if err != nil {
			return nil, errors.New("netlink.NewAttributeeDecoder() " + err.Error())
		}

		for ad.Next() {
			switch ad.Type() {
			case nl80211.ATTR_BSS:
				ad.Do(ap.DecodeBSS)
				break
			default:
				break
			}
		}
		aps = append(aps, ap)
	}
	return aps, nil
}