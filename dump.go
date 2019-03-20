package main

import (
	"fmt"
	"github.com/google/gopacket"
	"log"
	"time"
)

func	monitorDump(monIfa *JamConn, apList *List, cliList *List, cliWList *List) {

	pktSrc := gopacket.NewPacketSource(monIfa.handle, monIfa.handle.LinkType())
	for !QuitG && time.Since(StatsG.sessionStart) < time.Second * time.Duration(OptsG.DumpDuration) {
		packet, err := pktSrc.NextPacket()
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
		monIfa.ChangeChanIfPast(time.Millisecond * 100)
	}
	dumpStr := sPrintDump(apList, cliList)
	fmt.Print(dumpStr)
}
