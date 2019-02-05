package main

import (
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/mdlayher/genetlink"
	"github.com/mdlayher/netlink"
	"github.com/mdlayher/wifi"
	"github.com/remyoudompheng/go-netlink/nl80211"
)

type Station struct {
	BSSID string
	SSID [6]uint
}

func help() {

	fmt.Printf("useage: ./%s <interface> <whitelist>\n", os.Args[0])
	os.Exit(1)
}

func triggerScan(conn *genetlink.Conn, fam *genetlink.Family, iface *wifi.Interface) error {
	encoder := netlink.NewAttributeEncoder()
	encoder.Uint32(nl80211.ATTR_IFINDEX, uint32(iface.Index))
	ifaceAttrib, err := encoder.Encode()
	if err != nil {
		log.Panicln(err)
	}
	req := genetlink.Message {
		Header: genetlink.Header {
			Command: nl80211.CMD_TRIGGER_SCAN,
			Version: fam.Version,
		},
		Data: ifaceAttrib,
	}
	flags := netlink.HeaderFlagsRequest | netlink.HeaderFlagsAcknowledge
	msgs, err := conn.Execute(req, fam.ID, flags)
	if err != nil {
		log.Panicln("genetlink.Conn.Execute", err)
	}
	for _, v := range msgs {
		fmt.Println(v)
	}
	return nil
}

func getScanResults(conn *genetlink.Conn, fam *genetlink.Family) []genetlink.Message {
	req := genetlink.Message {
		Header: genetlink.Header {
			Command: nl80211.CMD_GET_SCAN,
			Version: fam.Version,
		},
	}
	flags := netlink.HeaderFlagsRequest | netlink.HeaderFlagsDump
	msgs, err := conn.Execute(req, fam.ID, flags)
	if err != nil {
		log.Panicln("genetlink.Conn.Execute()", err)
	}
	for _, v := range msgs {
		fmt.Println(v)
	}
	return msgs
}

func getInterface(targetIface string) (* wifi.Interface, error) {
	client, err := wifi.New()
	var ret *wifi.Interface = nil

	if err != nil {
		log.Panicln(err)
	}
	defer func(){
		if err := client.Close(); err != nil {
			log.Panicln(err)
		}
	}()
	ifaces, err := client.Interfaces()
	if err != nil {
		log.Panicln(err)
	}
	for _, v := range ifaces {
		if v.Name == targetIface {
			ret = v
		}
	}
	if ret == nil {
		return nil, fmt.Errorf("interface %s not found", targetIface)
	}
	return ret, nil
}

func getNL80211ScanMCID(fam *genetlink.Family) (uint32, error) {
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


func main() {
	if len(os.Args) < 3 {
		help()
	}
	iface, err := getInterface(os.Args[1])
	if err != nil {
		log.Fatalln(err)
	}
	conn, err := genetlink.Dial(nil)
	if err != nil {
		log.Fatalln("genetlink.Dial()", err)
	}
	defer func() {
		if err := conn.Close(); err != nil {
			log.Fatalln("genetlink.Conn.Close()", err)
		}
	}()
	fam, err := getNL80211Family(conn)
	if err != nil {
		log.Fatalln(err)
	}
	scanMCID, err := getNL80211ScanMCID(fam)
	if err := conn.JoinGroup(scanMCID); err != nil {
		log.Fatalln("genetlink.Conn.JoinGroup()", err)
	}
	if err := triggerScan(conn, fam, iface); err != nil {
		log.Fatalln(err)
	}
	stations := getScanResults(conn, fam)
	for _, v := range stations {
		fmt.Println(v)
	}
}
