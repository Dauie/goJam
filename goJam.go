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



func help() {

	fmt.Printf("useage: ./%s <interface> <whitelist>\n", os.Args[0])
	os.Exit(1)
}

func triggerScan(conn *genetlink.Conn, fam *genetlink.Family, iface *wifi.Interface) error {
	var done bool = false
	var failed bool = false

	encoder := netlink.NewAttributeEncoder()
	encoder.Uint32(nl80211.ATTR_IFINDEX, uint32(iface.Index))
	encoder.Bytes(nl80211.ATTR_SCAN_SSIDS, []byte(""))
	attribs, err := encoder.Encode()
	if err != nil {
		log.Panicln("genetlink.Encoder.Encode()", err)
	}
	req := genetlink.Message {
		Header: genetlink.Header {
			Command: nl80211.CMD_TRIGGER_SCAN,
			Version: fam.Version,
		},
		Data: attribs,
	}
	flags := netlink.HeaderFlagsRequest | netlink.HeaderFlagsAcknowledge
	validateMsg, err := conn.Send(req, fam.ID, flags)
	if err != nil {
		log.Panicln("genetlink.Conn.Send()", err)
	}
	fmt.Println("Message sent: ", validateMsg)
	for !done && !failed {
		msgs, _, err := conn.Receive()
		if err != nil {
			fmt.Println(err)
		}
		for _, m := range msgs {
			switch m.Header.Command {
			case nl80211.CMD_NEW_SCAN_RESULTS:
				fmt.Println("")
				done = true
				break
			case nl80211.CMD_SCAN_ABORTED:
				failed = true
				fmt.Println("SCAN ABORTED, trying again...")
				if err := triggerScan(conn, fam, iface); err != nil {
					log.Panicln(err)
				}
				break
			default:
				fmt.Println("cmd type: ", m.Header.Command, " skipped")
				break
			}
		}
	}
	return nil
}

type Station struct {
	BSSID []byte
	SSID string
}

func (s * Station) decodeBSSIE(b []byte) error {
	fmt.Println("in BSSIE")
	ad, err := netlink.NewAttributeDecoder(b)
	if err != nil {
		return errors.New("netlink.NewAttributeDecoder() " + err.Error())
	}
	for ad.Next() {
		switch ad.Type() {
		case nl80211.ATTR_SSID:
			s.SSID = ad.String()
			fmt.Printf("got SSID %s\n", s.SSID)
			break
		default:
			fmt.Printf("BSSIE CODE: %02x\n",  ad.Type())
			break
		}
	}
	return nil
}

func (s * Station) decodeBSS(b []byte) error {
	ad, err := netlink.NewAttributeDecoder(b)
	if err != nil {
		return errors.New("netlink.NewAttributeDecoder() " + err.Error())
	}
	for ad.Next() {
		switch ad.Type() {
		case nl80211.BSS_BSSID:
			s.BSSID = ad.Bytes()
			fmt.Printf("got BSSID\n")
			break
		case nl80211.BSS_INFORMATION_ELEMENTS:
			ad.Do(s.decodeBSSIE)
			break
		default:
			fmt.Printf("BSS CODE: %02x\n",  ad.Type())
			break
		}
	}
	return nil
}

func decodeScanResults(msgs []genetlink.Message) []Station {
	var stations = new([]Station)
	fmt.Println(len(msgs))
	for i := 0; i < len(msgs); i++ {
		ad, err := netlink.NewAttributeDecoder(msgs[i].Data)
		if err != nil {
			log.Panicln("netlink.NewAttributeeDecoder()", err)
		}
		var ap Station
		for ad.Next() {
			switch ad.Type() {
			case nl80211.ATTR_BSS:
				ad.Do(ap.decodeBSS)
				break
			default:
				fmt.Printf(" %02x\n",  ad.Type())
				break
			}
		}
		fmt.Println("\nNew AP: ")
		*stations = append(*stations, ap)
	}
	return *stations
}
func getScanResults(conn *genetlink.Conn, fam *genetlink.Family, iface *wifi.Interface) []genetlink.Message {
//	var stations []Station

	encoder := netlink.NewAttributeEncoder()
	flags := netlink.HeaderFlagsRequest | netlink.HeaderFlagsDump
	encoder.Uint32(nl80211.ATTR_IFINDEX, uint32(iface.Index))
	attribs, err := encoder.Encode()
	if err != nil {
		log.Panicln("genetlink.Encoder.Encode()", err)
	}
	req := genetlink.Message {
		Header: genetlink.Header {
			Command: nl80211.CMD_GET_SCAN,
			Version: fam.Version,
		},
		Data: attribs,
	}
	msgs, err := conn.Execute(req, fam.ID, flags)
	if err != nil {
		log.Panicln("genetlink.Conn.Execute()", err)
	}
	decodeScanResults(msgs)
	return nil
}

func getInterface(targetIface string) (* wifi.Interface, error) {
	var ret *wifi.Interface = nil

	client, err := wifi.New()
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
	if err != nil {
		log.Fatalln("getNL80211ScanMCID()", err)
	}
	if err := conn.JoinGroup(scanMCID); err != nil {
		log.Fatalln("genetlink.Conn.JoinGroup()", err)
	}
	if err := triggerScan(conn, fam, iface); err != nil {
		log.Fatalln(err)
	}
	stations := getScanResults(conn, fam, iface)
	for _, v := range stations {
		fmt.Println(v)
	}
}
