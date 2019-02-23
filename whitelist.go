package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"
)

func getWhiteListFromFile() (List, error) {

	var whiteList List

	file, err := os.Open(os.Args[2])
	if err != nil {
		return List{}, errors.New("os.Open(): " + os.Args[3] + " " + err.Error())
	}
	fscanner := bufio.NewScanner(file)
	for fscanner.Scan() {
		ssid := strings.TrimSpace(fscanner.Text())
		whiteList.Add(ssid, true)
	}
	return whiteList, nil
}

func makeApWatchList(stations []Ap, whiteList *List) List {

	var apWatch List

	fmt.Printf("AP Watchlist\n")
	for _, v := range stations {
		if _, ok := whiteList.Get(v.SSID); !ok {
			fmt.Printf("%s - %s\n", v.SSID ,v.hwaddr.String())
			apWatch.Add(v.hwaddr.String()[0:16], v)
		}
	}
	return apWatch
}
