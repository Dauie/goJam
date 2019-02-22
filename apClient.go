package main

import (
	"errors"
	"github.com/google/gopacket/layers"
	"log"
	"net"
	"strings"

	"github.com/dauie/go-netlink/nl80211"
	"github.com/mdlayher/genetlink"
	"github.com/mdlayher/netlink"
)

type Client		struct {
	hwaddr      net.HardwareAddr
	radioTapHdr layers.RadioTap
	dot11Hdr    layers.Dot11
}

type Ap struct {
	hwaddr  net.HardwareAddr
	SSID    string
	Clients map[string]Client
	Freq    uint32
}

//this is kinda hacks, but genetlink.AttributeDecoder is having issues with BSS_IEs
// or maybe im just an idiot
func (s *Ap) getSSIDFromBSSIE(b []byte) error {

	ssidLen := uint(b[1])
	if ssidLen != 0 {
		s.SSID = strings.TrimSpace(string(b[2:ssidLen + 2]))
	} else {
		s.SSID = NoSSID
	}
	return nil
}

func (s *Ap) AddClient(client Client) {

	if s.Clients == nil {
		s.Clients = make(map[string]Client)
	}
	s.Clients[client.hwaddr.String()] = client
}

func (s *Ap) DelClient(addr net.HardwareAddr) {

	if s.Clients == nil {
		return
	}
	delete(s.Clients, addr.String())
}

func (s *Ap) GetClient(addr net.HardwareAddr) (bool, Client) {
	if s.Clients != nil {
		ok, client := s.Clients[addr.String()]
		return client, ok
	}
	return false, Client{}
}

func (s *Ap) DecodeBSS(b []byte) error {

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
		case nl80211.BSS_FREQUENCY:
			s.Freq = ad.Uint32()
		default:
			break
		}
	}
	return nil
}

func decodeScanResults(msgs []genetlink.Message) ([]Ap, error) {

	var aps = []Ap{}

	for _, v := range msgs {
		ad, err := netlink.NewAttributeDecoder(v.Data)
		if err != nil {
			return nil, errors.New("netlink.NewAttributeeDecoder() " + err.Error())
		}
		var ap Ap
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