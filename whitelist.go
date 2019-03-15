package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"
)

type keyDecorator func(string)string

func apKey(ap string) string {
	return ap[:16]
}

func getListFromFile(filename string, fn keyDecorator) (List, error) {

	var list	List

	if filename == "" {
		return list, nil
	}
	file, err := os.Open(filename)
	if err != nil {
		return List{}, errors.New("os.Open() " + filename + " " + err.Error())
	}
	defer func() {
		if err := file.Close(); err != nil {
			fmt.Println("os.File.Close()", err)
		}
	}()
	fscanner := bufio.NewScanner(file)
	for fscanner.Scan() {
		key := strings.TrimSpace(fscanner.Text())
		if fn != nil {
			list.Add(fn(key), key)
		}
		list.Add(key, key)
	}
	return list, nil
}

func appendApList(scanResults []AP, apList *List, apWList *List) List {

	var apWatch List

	if !OptsG.GuiMode {
		fmt.Printf("AP watchlist updating...\n")
	}
	for _, v := range scanResults {
		if _, ok := apWList.Get(apKey(v.hwaddr.String())); !ok {
			if !OptsG.GuiMode {
				fmt.Printf("%s - %s\n", v.ssid, v.hwaddr.String())
			}
			apList.Add(apKey(v.hwaddr.String()), v)
		}
	}
	return apWatch
}
