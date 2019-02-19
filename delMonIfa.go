package main

import (
	"log"
	"os"
)

func main() {

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
