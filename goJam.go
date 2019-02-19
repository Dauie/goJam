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

func checkComms(data *layers.Dot11, lastComms *List, aps *List) bool {
	var apMac net.HardwareAddr
	var clientMac net.HardwareAddr

	bssid := data.Address3
	if data.Address1.String() ==  bssid.String() {
		apMac = data.Address1
		clientMac = data.Address2
	} else {
		apMac = data.Address2
		clientMac = data.Address1
	}
	if apMac.String() != "" && apMac.String() != BroadcastAddr &&
		clientMac.String() != "" && clientMac.String() != BroadcastAddr {
		if a, ok := aps.Get(apMac.String()); ok {
			ap := a.(Station)
			if v, ok := lastComms.Get(clientMac.String()); ok {
				lastCom := v.(string)
				if lastCom != apMac.String() {
					if oap, ok := aps.Get(lastCom); ok {
						fmt.Printf("client %s moved from %s to %s\n", clientMac.String(), lastCom, apMac.String())
						oldAp := oap.(Station)
						oldAp.DelClient(clientMac)
					}
				}
			}
			lastComms.Add(clientMac.String(), apMac.String())
			ap.AddClient(clientMac)
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
	apList, err := utilIfa.DoAPScan(&whiteList)
	if err != nil {
		log.Fatalln("doAPScan()", err)
	}
	var clientList List
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
				checkComms(data, &clientList, &apList)
			}
		}
	}
		//monIfa.ChangeChanIfPast(time.Second * 2)
}

