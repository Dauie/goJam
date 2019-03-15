package main

type Channel struct {
	LowerFreq	uint32
	CenterFreq	uint32
	UpperFreq	uint32
	ChanWidth	uint32
}

var ActiveChanArrG []Channel

var ChanArrG = []Channel {
	{ LowerFreq: 2401, CenterFreq: 2412, UpperFreq: 2423, ChanWidth:  NL_80211_CHAN_WIDTH_20 },
	{ LowerFreq: 2406, CenterFreq: 2412, UpperFreq: 2428, ChanWidth:  NL_80211_CHAN_WIDTH_20 },
	{ LowerFreq: 2411, CenterFreq: 2422, UpperFreq: 2433, ChanWidth:  NL_80211_CHAN_WIDTH_20 },
	{ LowerFreq: 2416, CenterFreq: 2427, UpperFreq: 2438, ChanWidth:  NL_80211_CHAN_WIDTH_20 },
	{ LowerFreq: 2421, CenterFreq: 2432, UpperFreq: 2443, ChanWidth:  NL_80211_CHAN_WIDTH_20 },
	{ LowerFreq: 2426, CenterFreq: 2437, UpperFreq: 2448, ChanWidth:  NL_80211_CHAN_WIDTH_20 },
	{ LowerFreq: 2431, CenterFreq: 2442, UpperFreq: 2453, ChanWidth:  NL_80211_CHAN_WIDTH_20 },
	{ LowerFreq: 2436, CenterFreq: 2447, UpperFreq: 2458, ChanWidth:  NL_80211_CHAN_WIDTH_20 },
	{ LowerFreq: 2441, CenterFreq: 2452, UpperFreq: 2463, ChanWidth:  NL_80211_CHAN_WIDTH_20 },
	{ LowerFreq: 2446, CenterFreq: 2457, UpperFreq: 2468, ChanWidth: NL_80211_CHAN_WIDTH_20  },
	{ LowerFreq: 2451, CenterFreq: 2462, UpperFreq: 2473, ChanWidth: NL_80211_CHAN_WIDTH_20  },
	{ LowerFreq: 2456, CenterFreq: 2467, UpperFreq:	2478, ChanWidth: NL_80211_CHAN_WIDTH_20  },
	{ LowerFreq: 2461, CenterFreq: 2472, UpperFreq:	2483, ChanWidth: NL_80211_CHAN_WIDTH_20  },
	{ LowerFreq: 2473, CenterFreq: 2484, UpperFreq:	2495, ChanWidth: NL_80211_CHAN_WIDTH_20  },
	{ CenterFreq: 5180, ChanWidth: NL_80211_CHAN_WIDTH_40 },
	{ CenterFreq: 5200, ChanWidth: NL_80211_CHAN_WIDTH_40 },
	{ CenterFreq: 5220, ChanWidth: NL_80211_CHAN_WIDTH_40 },
	{ CenterFreq: 5240, ChanWidth: NL_80211_CHAN_WIDTH_40 },
	{ CenterFreq: 5260, ChanWidth: NL_80211_CHAN_WIDTH_40 },
	{ CenterFreq: 5280, ChanWidth: NL_80211_CHAN_WIDTH_40 },
	{ CenterFreq: 5300, ChanWidth: NL_80211_CHAN_WIDTH_40 },
	{ CenterFreq: 5320, ChanWidth: NL_80211_CHAN_WIDTH_40 },
	{ CenterFreq: 5500, ChanWidth: NL_80211_CHAN_WIDTH_40 },
	{ CenterFreq: 5520, ChanWidth: NL_80211_CHAN_WIDTH_40 },
	{ CenterFreq: 5540, ChanWidth: NL_80211_CHAN_WIDTH_40 },
	{ CenterFreq: 5560, ChanWidth: NL_80211_CHAN_WIDTH_40 },
	{ CenterFreq: 5580, ChanWidth: NL_80211_CHAN_WIDTH_40 },
	{ CenterFreq: 5600, ChanWidth: NL_80211_CHAN_WIDTH_40 },
	{ CenterFreq: 5620, ChanWidth: NL_80211_CHAN_WIDTH_40 },
	{ CenterFreq: 5640, ChanWidth: NL_80211_CHAN_WIDTH_40 },
	{ CenterFreq: 5660, ChanWidth: NL_80211_CHAN_WIDTH_40 },
	{ CenterFreq: 5680, ChanWidth: NL_80211_CHAN_WIDTH_40 },
	{ CenterFreq: 5700, ChanWidth: NL_80211_CHAN_WIDTH_40 },
	{ CenterFreq: 5745, ChanWidth: NL_80211_CHAN_WIDTH_40 },
	{ CenterFreq: 5765, ChanWidth: NL_80211_CHAN_WIDTH_40 },
	{ CenterFreq: 5785, ChanWidth: NL_80211_CHAN_WIDTH_40 },
	{ CenterFreq: 5805, ChanWidth: NL_80211_CHAN_WIDTH_40 },
	{ CenterFreq: 5825, ChanWidth: NL_80211_CHAN_WIDTH_40 },
}


var ChanMapG = map[uint32]Channel {
	2412: { LowerFreq: 2401, CenterFreq: 2412, UpperFreq: 2423, ChanWidth:  NL_80211_CHAN_WIDTH_20 },
	2417: { LowerFreq: 2406, CenterFreq: 2417, UpperFreq: 2428, ChanWidth:  NL_80211_CHAN_WIDTH_20 },
	2422: { LowerFreq: 2411, CenterFreq: 2422, UpperFreq: 2433, ChanWidth:  NL_80211_CHAN_WIDTH_20 },
	2427: { LowerFreq: 2416, CenterFreq: 2427, UpperFreq: 2438, ChanWidth:  NL_80211_CHAN_WIDTH_20 },
	2432: { LowerFreq: 2421, CenterFreq: 2432, UpperFreq: 2443, ChanWidth:  NL_80211_CHAN_WIDTH_20 },
	2437: { LowerFreq: 2426, CenterFreq: 2437, UpperFreq: 2448, ChanWidth:  NL_80211_CHAN_WIDTH_20 },
	2442: { LowerFreq: 2431, CenterFreq: 2442, UpperFreq: 2453, ChanWidth:  NL_80211_CHAN_WIDTH_20 },
	2447: { LowerFreq: 2436, CenterFreq: 2447, UpperFreq: 2458, ChanWidth:  NL_80211_CHAN_WIDTH_20 },
	2452: { LowerFreq: 2441, CenterFreq: 2452, UpperFreq: 2463, ChanWidth:  NL_80211_CHAN_WIDTH_20 },
	2457: { LowerFreq: 2446, CenterFreq: 2457, UpperFreq: 2468, ChanWidth: NL_80211_CHAN_WIDTH_20  },
	2462: { LowerFreq: 2451, CenterFreq: 2462, UpperFreq: 2473, ChanWidth: NL_80211_CHAN_WIDTH_20  },
	2467: { LowerFreq: 2456, CenterFreq: 2467, UpperFreq:	2478, ChanWidth: NL_80211_CHAN_WIDTH_20  },
	2472: { LowerFreq: 2461, CenterFreq: 2472, UpperFreq:	2483, ChanWidth: NL_80211_CHAN_WIDTH_20  },
	2484: { LowerFreq: 2473, CenterFreq: 2484, UpperFreq:	2495, ChanWidth: NL_80211_CHAN_WIDTH_20  },
	5180: { CenterFreq: 5180, ChanWidth: NL_80211_CHAN_WIDTH_40 },
	5200: { CenterFreq: 5200, ChanWidth: NL_80211_CHAN_WIDTH_40 },
	5220: { CenterFreq: 5220, ChanWidth: NL_80211_CHAN_WIDTH_40 },
	5240: { CenterFreq: 5240, ChanWidth: NL_80211_CHAN_WIDTH_40 },
	5260: { CenterFreq: 5260, ChanWidth: NL_80211_CHAN_WIDTH_40 },
	5280: { CenterFreq: 5280, ChanWidth: NL_80211_CHAN_WIDTH_40 },
	5300: { CenterFreq: 5300, ChanWidth: NL_80211_CHAN_WIDTH_40 },
	5320: { CenterFreq: 5320, ChanWidth: NL_80211_CHAN_WIDTH_40 },
	5500: { CenterFreq: 5500, ChanWidth: NL_80211_CHAN_WIDTH_40 },
	5520: { CenterFreq: 5520, ChanWidth: NL_80211_CHAN_WIDTH_40 },
	5540: { CenterFreq: 5540, ChanWidth: NL_80211_CHAN_WIDTH_40 },
	5560: { CenterFreq: 5560, ChanWidth: NL_80211_CHAN_WIDTH_40 },
	5580: { CenterFreq: 5580, ChanWidth: NL_80211_CHAN_WIDTH_40 },
	5600: { CenterFreq: 5600, ChanWidth: NL_80211_CHAN_WIDTH_40 },
	5620: { CenterFreq: 5620, ChanWidth: NL_80211_CHAN_WIDTH_40 },
	5640: { CenterFreq: 5640, ChanWidth: NL_80211_CHAN_WIDTH_40 },
	5660: { CenterFreq: 5660, ChanWidth: NL_80211_CHAN_WIDTH_40 },
	5680: { CenterFreq: 5680, ChanWidth: NL_80211_CHAN_WIDTH_40 },
	5700: { CenterFreq: 5700, ChanWidth: NL_80211_CHAN_WIDTH_40 },
	5745: { CenterFreq: 5745, ChanWidth: NL_80211_CHAN_WIDTH_40 },
	5765: { CenterFreq: 5765, ChanWidth: NL_80211_CHAN_WIDTH_40 },
	5785: { CenterFreq: 5785, ChanWidth: NL_80211_CHAN_WIDTH_40 },
	5805: { CenterFreq: 5805, ChanWidth: NL_80211_CHAN_WIDTH_40 },
	5825: { CenterFreq: 5825, ChanWidth: NL_80211_CHAN_WIDTH_40 },
}

func	contains(chanArr []Channel, chann uint32) bool {

	for _, v := range chanArr {
		if v.CenterFreq == chann {
			return true
		}
	}
	return false
}

func	remove(chanArr []Channel, chann uint32) []Channel {

	j := 0

	nArr := make([]Channel, len(chanArr))
	for i := 0; i < len(chanArr); i++ {
		if chanArr[i].CenterFreq == chann {
			continue
		}
		nArr[j] = chanArr[i]
		j += 1
	}
	return nArr
}
