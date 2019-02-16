package main

import (
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"syscall"
	"time"

	"github.com/dauie/go-netlink/nl80211"
	"github.com/google/gopacket/pcap"
	"github.com/mdlayher/genetlink"
	"github.com/mdlayher/netlink"
)

type JamConn struct {
	chanInx			int
	lastChanSwitch	time.Time
	nlconn			*genetlink.Conn
	ifa				*net.Interface
	fam				*genetlink.Family
	handle			*pcap.Handle
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

func (conn *JamConn) SetDeviceChannel(chann Channel) error {
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

func (conn *JamConn) sendScanAbort() error {
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

func (conn *JamConn) getScanResults() ([]Station, error) {

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
	//	bpfExpr = bpfExpr + fmt.Sprintf("ether host %s", v.BSSID.String())
	//	if i < ln {
	//		i++
	//		bpfExpr = bpfExpr + " or "
	//	}
	//}
	bpfExpr = fmt.Sprintf("not ether host %s", conn.ifa.HardwareAddr.String())
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
	if err := inactive.SetSnapLen(128); err != nil {
		log.Fatalln(err)
	}
	if err := inactive.SetTimeout(time.Second * 1); err != nil {
		log.Fatalln(err)
	}
	if err := inactive.SetRFMon(true); err != nil {
		log.Fatalln(err)
	}
	conn.handle, err = inactive.Activate()
	if err != nil {
		return errors.New("pcap.InactiveHandle.Activate()" + err.Error())
	}
	return nil
}

func (conn *JamConn) DoAPScan(whiteList *List) (macWatch List, err error) {
	scanMCID, err := getNL80211ScanMCID(conn.fam)
	if err := conn.nlconn.JoinGroup(scanMCID); err != nil {
		return List{}, errors.New("genetlink.Conn.JoinGroup() " + err.Error())
	}
	if ok, err := conn.triggerScan(); !ok {
		if err.Error() == "scan failed" {
			//retry scan once
			if ok, err := conn.triggerScan(); !ok {
				return List{}, errors.New("triggerScan() " + err.Error())
			}
		}
		return List{}, errors.New("triggerScan() " + err.Error())
	}
	stations, err := conn.getScanResults()
	if err != nil {
		return List{}, errors.New("getScanResults() " + err.Error())
	}
	if err := conn.nlconn.LeaveGroup(scanMCID); err != nil {
		return List{}, errors.New("genetlink.LeaveGroup() " + err.Error())
	}
	apWatchList := makeApWatchList(stations, whiteList)
	return apWatchList, nil
}

func (conn *JamConn) ChangeChanIfPast(timeout time.Duration) {
	var chann Channel

	if time.Since(conn.lastChanSwitch) > timeout {
		chann = ChansG[conn.chanInx]
		if conn.chanInx + 1 < len(ChansG) - 1 {
			conn.chanInx += 1
		} else {
			conn.chanInx = 1
		}
		fmt.Println("trying: ", chann)
		if err := conn.SetDeviceChannel(chann);
			err != nil {
			log.Printf("error changing frequency %s", err.Error())
		} else {
			log.Printf("chan switched to %dMhz", chann.CenterFreq)
		}
		conn.lastChanSwitch = time.Now()
	}
}

func (conn* JamConn) triggerScan() (bool, error) {
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

func getInterface(targetIface string) (net.Interface, error) {

	ifaces, err := net.Interfaces()
	if err != nil {
		return net.Interface{}, errors.New("net.Interfaces() " + err.Error())
	}
	for _, v := range ifaces {
		if v.Name == targetIface {
			return v, nil
		}
	}
	return net.Interface{}, fmt.Errorf("interface %s not found", targetIface)
}

func getNL80211ScanMCID(fam *genetlink.Family) (uint32, error) {

	scanMCID := uint32(0)
	for _, v := range fam.Groups {
		fmt.Println(v.Name)
		if v.Name == "scan" {
			scanMCID = v.ID
		}
	}
	if scanMCID == 0 {
		return 0, errors.New("could not find nl80211 'scan' multicast ID")
	}
	return scanMCID, nil
}

func getNL80211Family(conn *genetlink.Conn) (* genetlink.Family, error) {

	fam, err := conn.GetFamily("nl80211")
	if err != nil {
		if os.IsNotExist(err) {
			return nil, errors.New("nl80211 not found on system" + err.Error())
		}
		return nil, err
	}
	return &fam, nil
}
