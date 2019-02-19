package main

const (
	BroadcastAddr = "ff:ff:ff:ff:ff:ff"
	NoSSID = "NO_SSID"
	EthAlen = 6
	DefPcapBufLen = 2 * 1024 * 1024
	MinEthFrameLen = 64
)

/*TODO add these to gonetlink/nl80211.h*/
const (
	ATTR_CHANNEL_WIDTH = 0x9f
	ATTR_CENTER_FREQ = 0xa0
)

const (
	NL_80211_CHAN_WIDTH_20_NOHT = 0x0
	NL_80211_CHAN_WIDTH_20 = 0x1
	NL_80211_CHAN_WIDTH_40 = 0x2
	NL_80211_CHAN_WIDTH_80 = 0x3
	NL_80211_CHAN_WIDTH_80P80 = 0x4
	NL_80211_CHAN_WIDTH_160 = 0x5
	NL_80211_CHAN_WIDTH_5 = 0x6
	NL_80211_CHAN_WIDTH_10 = 0x7
)
