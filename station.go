package main

import (
	"errors"
	"github.com/mdlayher/genetlink"
	"log"
	"net"
	"strings"

	"github.com/dauie/go-netlink/nl80211"
	"github.com/mdlayher/netlink"
)

type Station struct {
	BSSID net.HardwareAddr
	SSID string
	Freq uint32
}

//this is kinda hacks, but genetlink.AttributeDecoder is having issues with BSS_IEs
// or maybe im just an idiot
func (s *Station) getSSIDFromBSSIE(b []byte) error {
	ssidLen := uint(b[1])
	if ssidLen != 0 {
		s.SSID = strings.TrimSpace(string(b[2:ssidLen + 2]))
	} else {
		s.SSID = NoSSID
	}
	return nil
}

func (s * Station) DecodeBSS(b []byte) error {
	ad, err := netlink.NewAttributeDecoder(b)
	if err != nil {
		log.Panicln("netlink.NewAttributeDecoder() " + err.Error())
	}
	for ad.Next() {
		switch ad.Type() {
		case nl80211.BSS_BSSID:
			s.BSSID = ad.Bytes()
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

func decodeScanResults(msgs []genetlink.Message) ([]Station, error) {
	var stations = []Station{}
	for _, v := range msgs {
		ad, err := netlink.NewAttributeDecoder(v.Data)
		if err != nil {
			return nil, errors.New("netlink.NewAttributeeDecoder() " + err.Error())
		}
		var ap Station
		for ad.Next() {
			switch ad.Type() {
			case nl80211.ATTR_BSS:
				ad.Do(ap.DecodeBSS)
				break
			default:
				break
			}
		}
		stations = append(stations, ap)
	}
	return stations, nil
}