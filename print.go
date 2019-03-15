package main

import (
	"fmt"
	"sort"
)

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

func	sPrintfCliWList(cliWList *List) string {

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

func	sPrintfAPList(apList *List) string {

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

func	sPrintfAPWList(apWList *List) string {

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

func	sPrintfAssociation(apList *List, showAtkCnt bool) string {

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

func	sPrintfDump(apList *List, cliList *List) string {

	dumpStr := "--- monitor dump ---\n"
	dumpStr = dumpStr + "\nAPs\n"
	if len(apList.contents) > 0 {
		dumpStr = dumpStr + sPrintfAPList(apList)
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
	dumpStr = dumpStr + sPrintfAssociation(apList, false)
	return dumpStr
}
