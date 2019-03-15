package main

import "time"

type Stats			struct {
	nDeauth			uint32
	nDisassc		uint32
	nPktTx			uint64
	nByteTx			uint64
	nByteMon		uint64
	nPktMon			uint64
	sessionStart	time.Time
	sessionEnd		time.Time
}

func (s *Stats) SetSessionEnd(sessionEnd time.Time) {
	s.sessionEnd = sessionEnd
}

func (s *Stats) SetSessionStart(sessionStart time.Time) {
	s.sessionStart = sessionStart
}



