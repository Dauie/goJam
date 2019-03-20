# goJam :strawberry:

## What

goJam is a wifi "jammer" that utilizes deauthentication and disassociation frames to disrupt communication. The project is built using golang and utilizes netlink sockets for interface configuration and libpcap for packet capture and injection.

## Why

The reason I started this project was to render unauthorized APs on my campus useless.

##### Notice

I do not condone the malicious use of the program. Please use with caution and in a ethical and legal manner.

## try it

### prerequisites:
* linux (developed on Ubuntu 18.04 kernel 4.15.0-46-generic. This may work on mac, but I have not tested)
* wifi chipset and driver that supports monitor mode and packet injection (built using a Asus USB-AC56 & Alfa AU1900 using aircrack-ng rtl8812au & rtl8814au drivers respectively)
* golang
* make
* libpcap

### do the thing:
```git clone https://github.com/dauie/goJam.git && cd goJam && go get ./...```

```make```

```./goJam --help```

## Known issues
* intermitten success changing into 5Ghz band channels
* subsequent AP scans are mildly successful sometimes

## Future features:
* Automatic WPA handshake capture
* Configurable attack options for cli & gui

![alt text](https://github.com/Dauie/goJam/blob/master/goJamSS.png "goJam")
