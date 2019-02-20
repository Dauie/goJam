package main

import (
	"fmt"
	"log"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Printf("useage: ./%s <iface>", os.Args[0])
		os.Exit(1)
	}
	monIfa, err := NewJamConn(os.Args[1])
	if err != nil {
		log.Fatalln("NewJamConn() ", err)
	}
	defer func(){
		if err := monIfa.nlconn.Close(); err != nil {
			log.Fatalln("genetlink.Conn.Close() ", err)
		}
	}()
	if err := monIfa.DelMonIfa(); err != nil {
		log.Fatalln("JamConn.DelMonIfa()", err.Error())
	}
}
