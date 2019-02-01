package main

import (
	"fmt"
	"github.com/mdlayher/wifi"
	"log"
	"os"
)

func help() {
	fmt.Printf("useage: ./%s <interface> <whitelist>\n", os.Args[0])
	os.Exit(1)
}

func main() {
	if len(os.Args) < 3 {
		help()
	}
	client, err := wifi.New()
	if err != nil {
		log.Panicln(err)
	}
	defer func() {
		if err := client.Close(); err != nil {
			log.Panicln(err)
		}
	}()

	var iface *wifi.Interface = nil
	ifaceArr, err := client.Interfaces()
	if err != nil {
		log.Panicln(err)
	}
	for _, v := range ifaceArr {
		if v.Name == os.Args[1] {
			iface = v
		}
	}
	if iface == nil {
		log.Fatalf("unknown interface '%s'", os.Args[1])
	}

	bss, err := client.BSS(iface)
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Println(bss)
	stations, err := client.StationInfo(iface)
	if err != nil {
		log.Fatalln(err)
	}
	for _, v := range stations {
		fmt.Println(v)
	}
}
