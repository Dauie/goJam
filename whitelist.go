package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"
)

func getListFromFile(filename string) (List, error) {

	var list List

	if filename == "" {
		return list, nil
	}
	file, err := os.Open(filename)
	if err != nil {
		return List{}, errors.New("os.Open() " + filename + " " + err.Error())
	}
	fscanner := bufio.NewScanner(file)
	for fscanner.Scan() {
		key := strings.TrimSpace(fscanner.Text())
		list.Add(key, true)
	}
	return list, nil
}

func	appendApWatchList(scanResults []Ap, aps *List, whiteList *List) List {

	var apWatch List

	fmt.Printf("AP watchlist updating...\n")
	for _, v := range scanResults {
		if _, ok := whiteList.Get(v.ssid); !ok {
			if _, ok := aps.Get(v.hwaddr.String()[0:16]); !ok {
				fmt.Printf("%s - %s\n", v.ssid,v.hwaddr.String())
				//TODO find a way to limit this by antenna count
				//leave off the last character to catch devices with multiple anten.
				aps.Add(v.hwaddr.String()[0:16], v)
			}
		}
	}
	return apWatch
}
