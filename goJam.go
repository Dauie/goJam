package main

import (
	"bufio"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/dauie/go-netlink/nl80211"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/mdlayher/genetlink"
	"github.com/mdlayher/netlink"
)

const NoSSID = "NO_SSID"

const EthAlen = 6

const DefPcapBufLen = 2 * 1024 * 1024

const MinEthFrameLen = 64

const (
	ATTR_CHANNEL_WIDTH = 0x9f
	ATTR_CENTER_FREQ = 0xa0
)

const (
	NL_80211_CHAN_WIDTH_20_NOHT = 0x0
	NL_80211_CHAN_WIDTH_20 = 0x1
	NL_80211_CHAN_WIDTH_40 = 0x2
	NL_80211_CHAN_WIDTH_80 = 0x3
	NL_80211_CHAN_WIDTH_80P80 = 0x4
	NL_80211_CHAN_WIDTH_160 = 0x5
	NL_80211_CHAN_WIDTH_5 = 0x6
	NL_80211_CHAN_WIDTH_10 = 0x7
)

var (
	Chan24G  = map[int]Channel {
		1: { LowerFreq: 2401, CenterFreq: 2412, UpperFreq: 2423 },
		2: { LowerFreq: 2406, CenterFreq: 2412, UpperFreq: 2428 },
		3: { LowerFreq: 2411, CenterFreq: 2422, UpperFreq: 2433 },
		4: { LowerFreq: 2416, CenterFreq: 2427, UpperFreq: 2438 },
		5: { LowerFreq: 2421, CenterFreq: 2432, UpperFreq: 2443 },
		6: { LowerFreq: 2426, CenterFreq: 2437, UpperFreq: 2448 },
		7: { LowerFreq: 2431, CenterFreq: 2442, UpperFreq: 2453 },
		8: { LowerFreq: 2436, CenterFreq: 2447, UpperFreq: 2458 },
		9: { LowerFreq: 2441, CenterFreq: 2452, UpperFreq: 2463 },
		10: { LowerFreq: 2446, CenterFreq: 2457, UpperFreq: 2468 },
		11: { LowerFreq: 2451, CenterFreq: 2462, UpperFreq: 2473 },
		12: { LowerFreq: 2456, CenterFreq: 2467, UpperFreq:	2478 },
		13: { LowerFreq: 2461, CenterFreq: 2472, UpperFreq:	2483 },
		14: { LowerFreq: 2473, CenterFreq: 2484, UpperFreq:	2495 },
	}

	Chan50G = map[int]Channel {

		  36: { CenterFreq: 5180 },
		  40: { CenterFreq: 5200 },
		  44: { CenterFreq: 5220 },
		  48: { CenterFreq: 5240 },
		  52: { CenterFreq: 5260 },
		  56: { CenterFreq: 5280 },
		  60: { CenterFreq: 5300 },
		  64: { CenterFreq: 5320 },
		  100: { CenterFreq: 5500 },
		  104: { CenterFreq: 5520 },
		  108: { CenterFreq: 5540 },
		  112: { CenterFreq: 5560 },
		  116: { CenterFreq: 5580 },
		  120: { CenterFreq: 5600 },
		  124: { CenterFreq: 5620 },
		  128: { CenterFreq: 5640 },
		  132: { CenterFreq: 5660 },
		  136: { CenterFreq: 5680 },
		  140: { CenterFreq: 5700 },
		  149: { CenterFreq: 5745 },
		  153: { CenterFreq: 5765 },
		  157: { CenterFreq: 5785 },
		  161: { CenterFreq: 5805 },
		  165: { CenterFreq: 5825 },
	}
)

var QuitSIGINT = false

type Type interface{}

type Value Type

type List struct {
	contents map[string]Value
}

type Channel struct {
	ChanNum int
	LowerFreq int
	CenterFreq int
	UpperFreq int
	ChanWidth int
}

func (l* List)Get(key string) (Value, bool){
	val, ok := l.contents[key]
	return val, ok
}

func (l* List)Del(key string){
	delete(l.contents, key)
}

func (l* List)Add(key string, val Value) {
	if l.contents == nil {
		l.contents = make(map[string]Value)
	}
	l.contents[key] = val
}

type Station struct {
	BSSID net.HardwareAddr
	SSID string
	Freq uint32
}

func help() {
	fmt.Printf("useage: ./%s <util iface> <mon iface> <whitelist>\n", os.Args[0])
	os.Exit(1)
}

func setDeviceChannel(freq uint32, conn *genetlink.Conn, ifa *net.Interface, fam *genetlink.Family) error {
	encoder := netlink.NewAttributeEncoder()

	encoder.Uint32(nl80211.ATTR_IFINDEX, uint32(ifa.Index))
	encoder.Uint32(nl80211.ATTR_WIPHY_FREQ, freq)
	var width uint32
	if freq < 5000 {
		width = NL_80211_CHAN_WIDTH_20
	} else {
		width = NL_80211_CHAN_WIDTH_40
	}
	encoder.Uint32(ATTR_CHANNEL_WIDTH, width)
	encoder.Uint32(ATTR_CENTER_FREQ, freq)
	attribs, err := encoder.Encode()
	if err != nil {
		return errors.New("genetlink.Encoder.Encode() " + err.Error())
	}
	req := genetlink.Message {
		Header: genetlink.Header {
			Command: nl80211.CMD_SET_CHANNEL,
			Version: fam.Version,
		},
		Data: attribs,
	}
	flags := netlink.HeaderFlagsRequest | netlink.HeaderFlagsAcknowledge
	_, err = conn.Execute(req, fam.ID, flags)
	if err != nil {
		return errors.New("genetlink.Conn.Execute() " + err.Error())
	}
	return nil
}

func sendScanAbort(conn *genetlink.Conn, fam *genetlink.Family,
					iface *net.Interface) error {
	encoder := netlink.NewAttributeEncoder()
	encoder.Uint32(nl80211.ATTR_IFINDEX, uint32(iface.Index))
	attribs, err := encoder.Encode()
	if err != nil {
		return errors.New("genetlink.Encoder.Encode() " + err.Error())
	}
	req := genetlink.Message {
		Header: genetlink.Header {
			Command: nl80211.CMD_ABORT_SCAN,
			Version: fam.Version,
		},
		Data: attribs,
	}
	flags := netlink.HeaderFlagsRequest
	_, err = conn.Execute(req, fam.ID, flags)
	if err != nil {
		if err != syscall.ENOENT {
			return errors.New("genetlink.Conn.Execute() " + err.Error())
		} else {
			log.Println("no active scan")
		}
	} else {
		fmt.Println("scan aborted")
	}
	return nil
}

func triggerScan(conn *genetlink.Conn, fam *genetlink.Family,
					iface *net.Interface) (bool, error) {
	encoder := netlink.NewAttributeEncoder()
	encoder.Uint32(nl80211.ATTR_IFINDEX, uint32(iface.Index))
	// wildcard scan
	encoder.Bytes(nl80211.ATTR_SCAN_SSIDS, []byte(""))
	attribs, err := encoder.Encode()
	if err != nil {
		return false, errors.New("genetlink.Encoder.Encode() " + err.Error())
	}
	req := genetlink.Message {
		Header: genetlink.Header {
			Command: nl80211.CMD_TRIGGER_SCAN,
			Version: fam.Version,
		},
		Data: attribs,
	}
	flags := netlink.HeaderFlagsRequest
	_, err = conn.Send(req, fam.ID, flags)
	if err != nil {
		return false, errors.New("genetlink.Conn.Send() " + err.Error())
	}
	done := false
	for !done {
		msgs, _, err := conn.Receive()
		if err != nil {
			return false, errors.New("genetlink.Conn.Recieve() " + err.Error())
		}
		for _, m := range msgs {
			switch m.Header.Command {
			case nl80211.CMD_NEW_SCAN_RESULTS:
				done = true
				break
			case nl80211.CMD_SCAN_ABORTED:
				return false, errors.New("scan failed")
			default:
				break
			}
		}
	}
	return true, nil
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

func getScanResults(conn *genetlink.Conn, fam *genetlink.Family,
					iface *net.Interface) ([]Station, error) {

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

func getNL80211ScanMCID(fam *genetlink.Family) (uint32, error) {

	scanMCID := uint32(0)
	for _, v := range fam.Groups {
		fmt.Println(v.Name)
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

func getWhiteListFromFile() List {
	var whiteList List

	file, err := os.Open(os.Args[3])
	if err != nil {
		log.Panicln()
	}
	fscanner := bufio.NewScanner(file)
	for fscanner.Scan() {
		ssid := strings.TrimSpace(fscanner.Text())
		whiteList.Add(ssid, true)
	}
	return whiteList
}

func makeApWatchList(stations []Station, whiteList *List) List {
	var apWatch List
	fmt.Printf("AP Watchlist\n")
	for _, v := range stations {
		if _, ok := whiteList.Get(v.SSID); !ok {
			fmt.Printf("%s - %s\n", v.SSID ,v.BSSID.String())
			apWatch.Add(v.BSSID.String(), v)
		}
	}
	return apWatch
}

func setFilterForTargets(handle *pcap.Handle, p *net.Interface) error {
	var bpfExpr string
	//var i = 0
	//var ln = len(targetList) - 1

	//for _, v := range targetList {
	//	bpfExpr = bpfExpr + fmt.Sprintf("ether host %s", v.BSSID.String())
	//	if i < ln {
	//		i++
	//		bpfExpr = bpfExpr + " or "
	//	}
	//}
	bpfExpr = fmt.Sprintf("not ether host %s", p.HardwareAddr.String())
	if err := handle.SetBPFFilter(bpfExpr); err != nil {
			return errors.New("pcap.Handle.SetPBFFilter() " + err.Error())
	}
	return nil
}

func setupPcapHandle(iface *net.Interface) (*pcap.Handle, error) {
	inactive, err := pcap.NewInactiveHandle(iface.Name)
	defer inactive.CleanUp()
	if err != nil {
		log.Fatalln("pcap.NewInactiveHandle() ", err)
	}
	if err := inactive.SetBufferSize(DefPcapBufLen); err != nil {
		log.Fatalln(err)
	}
	if err := inactive.SetSnapLen(128); err != nil {
		log.Fatalln(err)
	}
	if err := inactive.SetTimeout(time.Second * 1); err != nil {
		log.Fatalln(err)
	}
	if err := inactive.SetRFMon(true); err != nil {
		log.Fatalln(err)
	}
	handle, err := inactive.Activate()
	if err != nil {
		return nil, errors.New("pcap.InactiveHandle.Activate()" + err.Error())
	}
	return handle, nil
}

func checkComms(src net.HardwareAddr, dst net.HardwareAddr, clients *List,
				aps *List, kosAPs *List ) bool {
	if v, ok := clients.Get(src.String()); ok {
		oldMac := v.(string)
		if dst.String() != oldMac {
			v, _ := aps.Get(oldMac)
			s := v.(Station)
			ap := Station{
				SSID:  s.SSID,
				BSSID: dst,
			}
			kosAPs.Add(dst.String(), ap)
			clients.Del(src.String())
			fmt.Printf("\nKill on site mac added: %s\n", dst.String())
			return true
		}
	}
	return false
}

func setupNLConn() (*genetlink.Conn, *genetlink.Family, error) {
	conn, err := genetlink.Dial(nil)
	if err != nil {
		return nil, nil, errors.New("genetlink.Dial() " + err.Error())
	}
	fam, err := getNL80211Family(conn)
	if err != nil {
		return nil, nil, errors.New("getNL80211Family() " + err.Error())
	}
	return conn, fam, nil
}

func doAPScan(conn *genetlink.Conn, fam *genetlink.Family, p *net.Interface,
				whiteList *List) (macWatch List, err error) {
	scanMCID, err := getNL80211ScanMCID(fam)
	if err := conn.JoinGroup(scanMCID); err != nil {
		return List{}, errors.New("genetlink.Conn.JoinGroup() " + err.Error())
	}
	if ok, err := triggerScan(conn, fam, p); !ok {
		if err.Error() == "scan failed" {
			//retry scan once
			if ok, err := triggerScan(conn, fam, p); !ok {
				return List{}, errors.New("triggerScan() " + err.Error())
			}
		}
		return List{}, errors.New("triggerScan() " + err.Error())
	}
	stations, err := getScanResults(conn, fam, p)
	if err != nil {
		return List{}, errors.New("getScanResults() " + err.Error())
	}
	if err := conn.LeaveGroup(scanMCID); err != nil {
		return List{}, errors.New("genetlink.LeaveGroup() " + err.Error())
	}
	apWatchList := makeApWatchList(stations, whiteList)
	return apWatchList, nil
}

func main() {
	if len(os.Args) < 4 {
		help()
	}
	sigc := make(chan os.Signal, 1)
	go func () {
		s := <-sigc
		if s == syscall.SIGINT {
			QuitSIGINT = true
		}
	}()
	signal.Notify(sigc, syscall.SIGINT)
	fmt.Println(os.Args[1], "\t", os.Args[2])
	utilIfa, err := getInterface(os.Args[1])
	if err != nil {
		log.Fatalln(err)
	}
	monIfa, err := getInterface(os.Args[2])
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Println("mon: ", monIfa)
	fmt.Println("util: ", utilIfa)
	conn, fam, err := setupNLConn()
	defer func(){
		if err := conn.Close(); err != nil {
			log.Fatalln("genetlink.Conn.Close() ", err)
		}
	}()
	whiteList := getWhiteListFromFile()
	macWatchlist, err := doAPScan(conn, fam, &utilIfa, &whiteList)
	if err != nil {
		log.Fatalln("doAPScan()", err)
	}
	handle, err := setupPcapHandle(&monIfa)
	if err != nil {
		log.Fatalln("setupPcapHandle() ", err)
	}
	defer handle.Close()
	//if err := setFilterForTargets(handle, utilIfa); err != nil {
	//	log.Panicln(err)
	//}

	var cliWatchList List
	var KosAPMacs List
	sInx := 0
	sLen := len(macWatchlist.contents) - 1
	packSrc := gopacket.NewPacketSource(handle, handle.LinkType())
	lastChanSwitch := time.Now()
	for !QuitSIGINT {
		packet, err := packSrc.NextPacket()
		if err != nil {
			log.Println(err)
		}
		if packet != nil {
			data := packet.Data()
			fmt.Print(".")
			if len(data) >= MinEthFrameLen {
				dstMac := net.HardwareAddr(data[:6])
				srcMac := net.HardwareAddr(data[6:12])
				//fmt.Printf("dst: %s | src %s\n", dstMac.String(), srcMac.String())
				if ok := checkComms(srcMac, dstMac, &cliWatchList,  &macWatchlist, &KosAPMacs); ok {

				} else if ok := checkComms(dstMac, srcMac, &cliWatchList,  &macWatchlist, &KosAPMacs); ok {

				} else if _, ok := macWatchlist.Get(srcMac.String()); ok {
					fmt.Printf("\nadded client to watch list %s\n", dstMac.String())
					cliWatchList.Add(dstMac.String(), srcMac.String())
				} else if _, ok := macWatchlist.Get(dstMac.String()); ok {
					fmt.Printf("\nadded client to watch list %s\n", srcMac.String())
					cliWatchList.Add(srcMac.String(), dstMac.String())
				}
			}
		}
		if time.Since(lastChanSwitch) > time.Second * 20 {
			i := 0
			for _, v := range macWatchlist.contents {
				if i == sInx {
					station := v.(Station)
					if err := setDeviceChannel(station.Freq, conn, &monIfa, fam);
					err != nil {
						log.Printf("error changing frequency %s", err.Error())
					} else {
						log.Printf("chan switched to %dMhz", station.Freq)
					}
					if sInx + 1 >= sLen {
						sInx = 0
					} else {
						sInx++
					}
					lastChanSwitch = time.Now()
					break
				}
				i++
			}
		}
	}
}


