package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strings"
)

func getWhiteListFromFile() List {
	var whiteList List

	file, err := os.Open(os.Args[3])
	if err != nil {
		log.Panicln()
	}
	fscanner := bufio.NewScanner(file)
	for fscanner.Scan() {
		ssid := strings.TrimSpace(fscanner.Text())
		whiteList.Add(ssid, true)
	}
	return whiteList
}

func makeApWatchList(stations []Station, whiteList *List) List {
	var apWatch List
	fmt.Printf("AP Watchlist\n")
	for _, v := range stations {
		if _, ok := whiteList.Get(v.SSID); !ok {
			fmt.Printf("%s - %s\n", v.SSID ,v.BSSID.String())
			apWatch.Add(v.BSSID.String(), v)
		}
	}
	return apWatch
}
