default: build

src = goJam.go jamConn.go list.go apClient.go stats.go
src += chans.go ifaUtil.go constants.go whitelist.go gui.go print.go dump.go

build:
	go build $(src)

clean:
	@rm goJam

#Makes a separate binary for deleteing the softmac device made by goJam
delmon:
	go build delMonIfa.go jamConn.go list.go apClient.go chans.go ifaUtil.go constants.go whitelist.go

makemon:
