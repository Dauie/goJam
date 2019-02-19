package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/dauie/go-netlink/nl80211"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
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
	defer func(){
		if err := utilIfa.nlconn.Close(); err != nil {
			log.Fatalln("genetlink.Conn.Close() ", err)
		}
	}()
	monIfa, err := NewJamConn(os.Args[2])
	if err != nil {
		log.Fatalln("NewJamConn() ", err)
	}
	defer func(){
		if err := monIfa.nlconn.Close(); err != nil {
			log.Fatalln("genetlink.Conn.Close() ", err)
		}
	}()
	//if err := monIfa.MakeMonIfa(); err != nil {
	//	log.Fatalln("JamConn.MakeMonIfa() ", err.Error())
	//}
	//defer func() {
	//	if err:= monIfa.DelMonIfa(); err != nil {
	//		log.Fatalln("JamConn.DelMonIfa()", err.Error())
	//	}
	//}()
	if err := monIfa.SetIfaType(nl80211.IFTYPE_MONITOR); err != nil {
		log.Fatalln("JamConn.SetIfaType()", err.Error())
	}
	defer func() {
		if err := monIfa.SetIfaType(nl80211.IFTYPE_STATION); err != nil {
			log.Fatalln("JamConn.SetIfaType()", err.Error())
		}
	}()
	if err = monIfa.SetupPcapHandle(); err != nil {
		log.Fatalln("setupPcapHandle() ", err)
	}
	defer monIfa.handle.Close()
	if err := monIfa.SetDeviceChannel(1); err != nil {
		log.Fatalln("JamConn.SetDeviceChannel()", err.Error())
	}

	whiteList := getWhiteListFromFile()
	macWatchlist, err := utilIfa.DoAPScan(&whiteList)
	if err != nil {
		log.Fatalln("doAPScan()", err)
	}
	var cliWatchList List
	var KosAPMacs List
	packSrc := gopacket.NewPacketSource(monIfa.handle, monIfa.handle.LinkType())
	monIfa.SetLastChanSwitch(time.Now())
	for !QuitSIGINT {
		packet, err := packSrc.NextPacket()
		if err != nil {
			if err.Error() != "Timeout Expired" {
				log.Fatalln("gopacket.PacketSource.NextPacket()", err.Error())
			}
		}
		if packet != nil {
			data80211 := packet.Layer(layers.LayerTypeDot11)
			if data80211 != nil {
				data := data80211.(*layers.Dot11)
				recvr := data.Address1
				transmttr := data.Address2
				dst := data.Address3
				src := data.Address4

				fmt.Printf("reciever: %s | trasmitter: %s | src: %s | dst: %s\n", recvr.String(), transmttr.String(), dst.String(), src.String())
				if ok := checkComms(src, dst, &cliWatchList,  &macWatchlist, &KosAPMacs); ok {

				} else if ok := checkComms(dst, src, &cliWatchList,  &macWatchlist, &KosAPMacs); ok {

				} else if _, ok := macWatchlist.Get(src.String()); ok {
					fmt.Printf("\nadded client to watch list %s\n", dst.String())
					cliWatchList.Add(dst.String(), src.String())
				} else if _, ok := macWatchlist.Get(dst.String()); ok {
					fmt.Printf("\nadded client to watch list %s\n", src.String())
					cliWatchList.Add(src.String(), dst.String())
				}
			}
		}
		//monIfa.ChangeChanIfPast(time.Second * 2)
	}
}
