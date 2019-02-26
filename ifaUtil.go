package main

import (
	"errors"
	"fmt"
	"net"
	"os"

	"github.com/mdlayher/genetlink"
)

func getInterface(targetIface string) (net.Interface, error) {

	ifaces, err := net.Interfaces()
	if err != nil {
		return net.Interface{}, errors.New("net.Interfaces() " + err.Error())
	}
	for _, v := range ifaces {
		if v.Name == targetIface {
			return v, nil
		}
	}
	return net.Interface{}, fmt.Errorf("interface %s not found", targetIface)
}

func getDot11ScanMCID(fam *genetlink.Family) (uint32, error) {

	scanMCID := uint32(0)
	for _, v := range fam.Groups {
		if v.Name == "scan" {
			scanMCID = v.ID
		}
	}
	if scanMCID == 0 {
		return 0, errors.New("could not find nl80211 'scan' multicast ID")
	}
	return scanMCID, nil
}

func getNL80211Family(conn *genetlink.Conn) (* genetlink.Family, error) {

	fam, err := conn.GetFamily("nl80211")
	if err != nil {
		if os.IsNotExist(err) {
			return nil, errors.New("nl80211 not found on system" + err.Error())
		}
		return nil, err
	}
	return &fam, nil
}

