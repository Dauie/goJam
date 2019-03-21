# goJam :strawberry:

## What

goJam is a wifi "jammer" that utilizes deauthentication and disassociation frames to disrupt communication. The project is built using golang and utilizes netlink sockets for interface configuration and libpcap for packet capture and injection.

## Why

The reason I started this project was to render unauthorized APs on my campus useless.

##### Notice

I do not condone the malicious use of the program. Please use with caution and in a ethical and legal manner.

## Try it

### Prerequisites:
* linux (developed on Ubuntu 18.04 kernel 4.15.0-46-generic. This should work on any modern linux distro, but I have not tested many)
* wifi chipset and driver that supports monitor mode and packet injection (built using a Asus USB-AC56 & Alfa AU1900 using aircrack-ng rtl88xxau driver)
* golang
* make
* libpcap

### Do the thing:
```git clone https://github.com/dauie/goJam.git && cd goJam && go get ./...```

```make```

```./goJam --help```

## Future features:
* Automatic WPA handshake capture
* Configurable attack options for cli & gui

## Known issues
* intermitten success changing into 5Ghz band channels
* subsequent AP scans are mildly successful sometimes




![alt text](https://github.com/Dauie/goJam/blob/master/goJamSS.png "goJam")
