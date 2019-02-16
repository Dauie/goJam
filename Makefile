default: build

build:
	go build goJam.go jamconn.go list.go station.go chans.go

clean:
	rm goJam