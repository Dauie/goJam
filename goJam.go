package main

import (
	"bufio"
	"errors"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/mdlayher/genetlink"
	"github.com/mdlayher/netlink"
	"github.com/mdlayher/wifi"
	"github.com/remyoudompheng/go-netlink/nl80211"
	"log"
	"net"
	"os"
	"strings"
	"time"
)

const NO_SSID = "SSID not broadcasted"

const ETH_ALEN = 6

type Station struct {
	BSSID net.HardwareAddr
	SSID string
}

func help() {

	fmt.Printf("useage: ./%s <interface> <whitelist>\n", os.Args[0])
	os.Exit(1)
}

func triggerScan(conn *genetlink.Conn, fam *genetlink.Family, iface *wifi.Interface) error {
	var done = false

	encoder := netlink.NewAttributeEncoder()
	encoder.Uint32(nl80211.ATTR_IFINDEX, uint32(iface.Index))
	// wildcard scan
	encoder.Bytes(nl80211.ATTR_SCAN_SSIDS, []byte(""))
	attribs, err := encoder.Encode()
	if err != nil {
		return errors.New("genetlink.Encoder.Encode() " + err.Error())
	}
	req := genetlink.Message {
		Header: genetlink.Header {
			Command: nl80211.CMD_TRIGGER_SCAN,
			Version: fam.Version,
		},
		Data: attribs,
	}
	flags := netlink.HeaderFlagsRequest | netlink.HeaderFlagsAcknowledge
	_, err = conn.Send(req, fam.ID, flags)
	if err != nil {
		return errors.New("genetlink.Conn.Send() " + err.Error())
	}
	for !done {
		msgs, _, err := conn.Receive()
		if err != nil {
			fmt.Println(err)
		}
		for _, m := range msgs {
			switch m.Header.Command {
			case nl80211.CMD_NEW_SCAN_RESULTS:
				done = true
				break
			case nl80211.CMD_SCAN_ABORTED:
				fmt.Println("SCAN ABORTED, trying again...")
				return triggerScan(conn, fam, iface)
			default:
				break
			}
		}
	}
	return nil
}


func hexPrint(b []byte) {
	for e, v := range b {
		fmt.Printf("%02x ", v)
		if (e + 1) % 4 == 0 {
			fmt.Printf("\t")
		}
		if (e + 1) % 16 == 0 {
			fmt.Printf("\n")
		}
	}
	fmt.Printf("\n")
}

//this is kinda hacks, but genetlink.AttributeDecoder is having issues with BSS_IEs
// or maybe im just an idiot
func (s *Station) getSSIDFromBSSIE(b []byte) error {
	ssidLen := uint(b[1])
	if ssidLen != 0 {
		s.SSID = strings.TrimSpace(string(b[2:ssidLen + 2]))
	} else {
		s.SSID = NO_SSID
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

func getScanResults(conn *genetlink.Conn, fam *genetlink.Family, iface *wifi.Interface) ([]Station, error) {

	encoder := netlink.NewAttributeEncoder()
	flags := netlink.HeaderFlagsRequest | netlink.HeaderFlagsDump
	encoder.Uint32(nl80211.ATTR_IFINDEX, uint32(iface.Index))
	attribs, err := encoder.Encode()
	if err != nil {
		return nil, errors.New("genetlink.Encoder.Encode() " + err.Error())
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
		return nil, errors.New("genetlink.Conn.Execute() " + err.Error())
	}
	return decodeScanResults(msgs)
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
		return nil, errors.New("wifi.Client.Interfaces() " + err.Error())
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

func printMac(bssid []byte) {
	for i := 0; i < ETH_ALEN; i++ {
		if i < ETH_ALEN - 1 {
			fmt.Printf("%02x:", bssid[i])
		} else {
			fmt.Printf("%02x\n", bssid[i])
		}
	}
}

func printStations(aps []Station) {
	for _, v  := range aps {
		if v.SSID == "" {
			v.SSID = "No broadcast"
		}
		fmt.Printf("%s - ", v.SSID)
		bssid := v.BSSID
		printMac(bssid)
	}
}

func getWhiteList() map[string]bool {
	wlist := map[string]bool{}
	file, err := os.Open(os.Args[2])
	if err != nil {
		log.Panicln()
	}
	fscanner := bufio.NewScanner(file)
	for fscanner.Scan() {
		ssid := strings.TrimSpace(fscanner.Text())
		wlist[ssid] = true
	}
	return wlist
}

func makeTargetList(stations []Station, wlist map[string]bool) map[string]Station {

	targets := map[string]Station {}
	for _, v := range stations {
		if _, ok := wlist[v.SSID]; !ok {
			targets[v.BSSID.String()] = v
		}
	}
	return targets
}

func setFilterForTargets(handle *pcap.Handle, targetList map[string]Station) error {
	var bpfExpr string
	var i = 0
	var ln = len(targetList) - 1

	for _, v := range targetList {
		bpfExpr = bpfExpr + fmt.Sprintf("ether host %s", v.BSSID.String())
		if i < ln {
			i++
			bpfExpr = bpfExpr + " or "
		}
	}
	fmt.Println(bpfExpr)
	if err := handle.SetBPFFilter(bpfExpr); err != nil {
		return errors.New("pcap.Handle.SetPBFFilter() " + err.Error())
	}
	return nil
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
		log.Fatalln("genetlink.Dial() ", err)
	}
	defer func() {
		if err := conn.Close(); err != nil {
			log.Fatalln("genetlink.Conn.Close() ", err)
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
		log.Fatalln("genetlink.Conn.JoinGroup() ", err)
	}
	if err := triggerScan(conn, fam, iface); err != nil {
		log.Fatalln(err)
	}
	stations, err := getScanResults(conn, fam, iface)
	if err != nil {
		log.Fatalln("getScanResults() ", err)
	}
	printStations(stations)
	wlist := getWhiteList()
	targList := makeTargetList(stations, wlist)
	for k := range wlist {
		fmt.Println(k)
	}
	for _, v := range targList {
		fmt.Printf("target: %s - %s\n", v.SSID, v.BSSID.String())
	}
	//var snapLen = 1024
	//var timeOut = 30 * time.Second
	//inactive, err := pcap.NewInactiveHandle(iface.Name)
	//if err != nil {
	//	log.Fatalln("pcap.NewInactiveHandle() ", err)
	//}
	//if err := inactive.SetPromisc(true); err != nil {
	//	log.Fatalln(err)
	//}
	//if err := inactive.SetRFMon(true); err != nil {
	//	log.Fatalln(err)
	//}
	//if err := inactive.SetImmediateMode(true); err != nil {
	//	log.Fatalln(err)
	//}
	//if err := inactive.SetSnapLen(256); err != nil {
	//	log.Fatalln(err)
	//}
	//if err := inactive.SetBufferSize(os.Getpagesize() * 3); err != nil {
	//	log.Fatalln(err)
	//}
	//if err := inactive.SetTimeout(time.Second * 10); err != nil {
	//	log.Fatalln(err)
	//}
	//handle, err := inactive.Activate()
	//if err != nil {
	//	log.Fatalln("pcap.InactiveHandle.Activate() ", err)
	//}
	//inactive.CleanUp()
	handle, err := pcap.OpenLive(iface.Name, 1024, true, time.Second * 15)
	if err != nil {
		log.Fatalln(err)
	}
	defer handle.Close()
	//if err := setFilterForTargets(handle, targList); err != nil {
	//	log.Panicln(err)
	//}
	packSrc := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packSrc.Packets() {
		eth := packet.Layer(layers.LayerTypeEthernet)
		ethPkt := eth.(*layers.Ethernet)
		fmt.Printf("dst: %s | src %s\n", ethPkt.DstMAC.String(), ethPkt.SrcMAC.String())
		if _, ok := targList[ethPkt.SrcMAC.String()]; ok {
			fmt.Printf("src ping")
		}
		if _, ok := targList[ethPkt.DstMAC.String()]; ok {
			fmt.Printf("dst zing")
		}
		//fmt.Print("src: ")
		//printMac(src)
		//fmt.Print("dst: ")
		//printMac(dst)
		//fmt.Println("\n")
	}
}

