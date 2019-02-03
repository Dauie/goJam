package main

import (
	"fmt"
	"github.com/mdlayher/genetlink"
	"github.com/mdlayher/netlink"
	"github.com/remyoudompheng/go-netlink/nl80211"
	"log"
	"os"
)


type Station struct {
	BSSID string
	SSID [6]uint
}

func help() {

	fmt.Printf("useage: ./%s <interface> <whitelist>\n", os.Args[0])
	os.Exit(1)
}

func triggerScan(conn *genetlink.Conn, fam *genetlink.Family) error {
	req := genetlink.Message{
		Header: genetlink.Header{
			Command: nl80211.CMD_TRIGGER_SCAN,
			Version: fam.Version,
		},
	}
	flags := netlink.HeaderFlagsRequest | netlink.HeaderFlagsDump
	_, err := conn.Execute(req, fam.ID, flags)
	if err != nil {
		log.Panicln("genetlink.Conn.Execute()", err)
	}
	return nil
}

func getScanResults(conn *genetlink.Conn, fam *genetlink.Family) []genetlink.Message {
	req := genetlink.Message{
		Header: genetlink.Header{
			Command: nl80211.CMD_GET_SCAN,
			Version: fam.Version,
		},
	}
	flags := netlink.HeaderFlagsRequest | netlink.HeaderFlagsDump
	stations, err := conn.Execute(req, fam.ID, flags)
	if err != nil {
		log.Panicln("genetlink.Conn.Execute()", err)
	}
	return stations
}

func parseScanResults() {

}


func main() {

	if len(os.Args) < 3 {
		help()
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
	fam, err := conn.GetFamily("nl80211")
	if err != nil {
		if os.IsNotExist(err) {
			log.Fatal("nl80211 not found on system", err)
		}
		log.Fatalln("genetlink.Conn.GetFamily('nl80211')", err)
	}
	scanMCID := uint32(0)
	for _,v := range fam.Groups {
		fmt.Println(v)
		if v.Name == "scan" {
			scanMCID = v.ID
		}
	}
	if scanMCID == 0 {
		log.Fatalln("could not find nl80211 'scan' multicast ID")
	}
	if err := conn.JoinGroup(scanMCID); err != nil {
		log.Fatalln("genetlink.Conn.JoinGroup()", err)
	}
	if err := triggerScan(conn, &fam); err != nil {
		log.Fatalln(err)
	}
	stations := getScanResults(conn, &fam)
	for _, v := range stations {
		fmt.Println(v)
	}
}
