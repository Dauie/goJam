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
	defer func(){
		if err := file.Close(); err != nil {
			fmt.Println("os.File.Close()", err)
		}
	}()
	fscanner := bufio.NewScanner(file)
	for fscanner.Scan() {
		key := strings.TrimSpace(fscanner.Text())
		list.Add(key, true)
	}
	return list, nil
}

func appendApList(scanResults []AP, apList *List, apWList *List) List {

	var apWatch List

	if !OptsG.GuiMode {
		fmt.Printf("AP watchlist updating...\n")
	}
	for _, v := range scanResults {
		if _, ok := apWList.Get(v.ssid); !ok {
			if _, ok := apList.Get(v.hwaddr.String()[:16]); !ok {
				if !OptsG.GuiMode {
					fmt.Printf("%s - %s\n", v.ssid,v.hwaddr.String())
				}
				apList.Add(v.hwaddr.String()[:16], v)
			}
		}
	}
	return apWatch
}
