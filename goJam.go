package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/google/gopacket"
)

/*
**
** Const Globals
**
*/

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

var QuitSIGINT = false

func help() {
	fmt.Printf("useage: ./%s <util iface> <mon iface> <whitelist>\n", os.Args[0])
	os.Exit(1)
}

func handleSignals() {
	sigc := make(chan os.Signal, 1)
	go func () {
		s := <-sigc
		if s == syscall.SIGINT {
			QuitSIGINT = true
		}
	}()
	signal.Notify(sigc, syscall.SIGINT)
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

func main() {
	if len(os.Args) < 4 {
		help()
	}
	handleSignals()
	utilIfa, err := NewJamConn(os.Args[1])
	if err != nil {
		log.Fatalln("NewJamConn() ", err)
	}
	monIfa, err := NewJamConn(os.Args[2])
	if err != nil {
		log.Fatalln("NewJamConn() ", err)
	}
	defer func(){
		if err := utilIfa.nlconn.Close(); err != nil {
			log.Fatalln("genetlink.Conn.Close() ", err)
		}
		if err := monIfa.nlconn.Close(); err != nil {
			log.Fatalln("genetlink.Conn.Close() ", err)
		}
	}()
	whiteList := getWhiteListFromFile()
	macWatchlist, err := utilIfa.DoAPScan(&whiteList)
	if err != nil {
		log.Fatalln("doAPScan()", err)
	}
	err = monIfa.SetupPcapHandle()
	if err != nil {
		log.Fatalln("setupPcapHandle() ", err)
	}
	defer monIfa.handle.Close()
	var cliWatchList List
	var KosAPMacs List
	packSrc := gopacket.NewPacketSource(monIfa.handle, monIfa.handle.LinkType())
	monIfa.SetLastChanSwitch(time.Now())
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
		monIfa.ChangeChanIfPast(time.Second * 2)
	}
}


