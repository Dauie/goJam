package main

type Channel struct {
	LowerFreq	uint32
	CenterFreq	uint32
	UpperFreq	uint32
	ChanWidth	uint32
}

var (
	ChanArrG = []Channel {
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
		//{ CenterFreq: 5180, ChanWidth: NL_80211_CHAN_WIDTH_40 },
		//{ CenterFreq: 5200, ChanWidth: NL_80211_CHAN_WIDTH_40 },
		//{ CenterFreq: 5220, ChanWidth: NL_80211_CHAN_WIDTH_40 },
		//{ CenterFreq: 5240, ChanWidth: NL_80211_CHAN_WIDTH_40 },
		//{ CenterFreq: 5260, ChanWidth: NL_80211_CHAN_WIDTH_40 },
		//{ CenterFreq: 5280, ChanWidth: NL_80211_CHAN_WIDTH_40 },
		//{ CenterFreq: 5300, ChanWidth: NL_80211_CHAN_WIDTH_40 },
		//{ CenterFreq: 5320, ChanWidth: NL_80211_CHAN_WIDTH_40 },
		//{ CenterFreq: 5500, ChanWidth: NL_80211_CHAN_WIDTH_40 },
		//{ CenterFreq: 5520, ChanWidth: NL_80211_CHAN_WIDTH_40 },
		//{ CenterFreq: 5540, ChanWidth: NL_80211_CHAN_WIDTH_40 },
		//{ CenterFreq: 5560, ChanWidth: NL_80211_CHAN_WIDTH_40 },
		//{ CenterFreq: 5580, ChanWidth: NL_80211_CHAN_WIDTH_40 },
		//{ CenterFreq: 5600, ChanWidth: NL_80211_CHAN_WIDTH_40 },
		//{ CenterFreq: 5620, ChanWidth: NL_80211_CHAN_WIDTH_40 },
		//{ CenterFreq: 5640, ChanWidth: NL_80211_CHAN_WIDTH_40 },
		//{ CenterFreq: 5660, ChanWidth: NL_80211_CHAN_WIDTH_40 },
		//{ CenterFreq: 5680, ChanWidth: NL_80211_CHAN_WIDTH_40 },
		//{ CenterFreq: 5700, ChanWidth: NL_80211_CHAN_WIDTH_40 },
		//{ CenterFreq: 5745, ChanWidth: NL_80211_CHAN_WIDTH_40 },
		//{ CenterFreq: 5765, ChanWidth: NL_80211_CHAN_WIDTH_40 },
		//{ CenterFreq: 5785, ChanWidth: NL_80211_CHAN_WIDTH_40 },
		//{ CenterFreq: 5805, ChanWidth: NL_80211_CHAN_WIDTH_40 },
		//{ CenterFreq: 5825, ChanWidth: NL_80211_CHAN_WIDTH_40 },
	}
)

var ChanMapG = map[uint16]Channel {
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
}
