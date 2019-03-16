package main

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

/*Thanks youngbasic.org! (https://yourbasic.org/golang/formatting-byte-size-to-human-readable-format)*/
func	ByteCountIEC(bytes uint64) string {

	const unit = 1024

	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB",
		float64(bytes)/float64(div), "KMGTPE"[exp])
}

func	sPrintTimeSince(then time.Time) string {
	now := time.Now()
	timeSince := now.Sub(then)
	timeStr := timeSince.String()
	decInx := strings.IndexRune(timeStr, '.')
	timeStr = timeStr[:decInx + 4] + "s"
	return timeStr
}

func	sPrintfCliList(cliList *List) string {

	var cliStr	string
	var cliArr	[]string

	CliListMutexG.Lock()
	for _, v := range cliList.contents {
		cli := (v).(*Client)
		c := fmt.Sprintf("%s\n", cli.hwaddr.String())
		cliArr = append(cliArr, c)
	}
	CliListMutexG.Unlock()
	sort.Strings(cliArr)
	for _, v := range cliArr {
		cliStr = cliStr + v
	}
	return cliStr
}

func	sPrintCliWList(cliWList *List) string {

	var cliStr	string
	var cliArr	[]string

	CliWListMutexG.Lock()
	for _, v := range cliWList.contents {
		cli := (v).(string)
		cliArr = append(cliArr, cli)
	}
	CliWListMutexG.Unlock()
	sort.Strings(cliArr)
	for _, v := range cliArr {
		cliStr = cliStr + v + "\n"
	}
	return cliStr
}

func	sPrintAPList(apList *List) string {

	var apStr	string
	var apArr	[]string

	APListMutexG.Lock()
	for _, v := range apList.contents {
		ap := (v).(AP)
		apArr = append(apArr, ap.ssid + " | " + ap.hwaddr.String())
	}
	APListMutexG.Unlock()
	sort.Strings(apArr)
	for _, v := range apArr {
		apStr = apStr + v + "\n"
	}
	return apStr
}

func	sPrintAPWList(apWList *List) string {

	var apStr	  string
	var apArr	[]string

	APWListMutexG.Lock()
	for _, v := range apWList.contents {
		ap := (v).(string)
		apArr = append(apArr, ap)
	}
	APWListMutexG.Unlock()
	sort.Strings(apArr)
	for _, v := range apArr {
		apStr = apStr + v + "\n"
	}
	return apStr
}

func	sPrintAssociation(apList *List, showAtkCnt bool) string {

	var c			string
	var assocStr	string
	var assocArr	[]string

	APListMutexG.Lock()
	for _, v := range apList.contents {
		ap := (v).(AP)
		apStr := fmt.Sprintf("%s | %s | %dMhz\n", ap.ssid, ap.hwaddr.String(), ap.freq)
		var cliArr []string
		for _, v := range ap.clients {
			if showAtkCnt {
				c = fmt.Sprintf("\t%s ˫ %d\n", v.hwaddr.String(), v.nDeauth)
			} else {
				c = fmt.Sprintf("\t%s\n", v.hwaddr.String())
			}
			cliArr = append(cliArr, c)
		}
		sort.Strings(cliArr)
		for _, v := range cliArr {
			apStr = apStr + v
		}
		assocArr = append(assocArr, apStr + "\n")
	}
	APListMutexG.Unlock()
	sort.Strings(assocArr)
	for _, v := range assocArr {
		assocStr = assocStr + v
	}
	return assocStr
}

func	sPrintDump(apList *List, cliList *List) string {

	dumpStr := "--- monitor dump ---\n"
	dumpStr = dumpStr + "\nAPs\n"
	if len(apList.contents) > 0 {
		dumpStr = dumpStr + sPrintAPList(apList)
	} else {
		dumpStr = dumpStr + "\nno APs...\n\n"
	}
	dumpStr = dumpStr + "\nClients\n"
	if len(cliList.contents) > 0 {
		dumpStr = dumpStr + sPrintfCliList(cliList)
	} else {
		dumpStr = dumpStr + "\nno clients...\n"
	}
	dumpStr = dumpStr + "\nAssociation\n"
	dumpStr = dumpStr + sPrintAssociation(apList, false)
	return dumpStr
}
