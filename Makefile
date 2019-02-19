default: build

build:
	go build goJam.go jamConn.go list.go station.go chans.go ifaUtil.go constants.go whitelist.go

clean:
	@rm goJam
	@rm delMonIfa

#Makes a separate binary for deleteing the softmac device made by goJam
delmon:
	go build delMonIfa.go jamConn.go list.go station.go chans.go ifaUtil.go constants.go whitelist.go

makemon: