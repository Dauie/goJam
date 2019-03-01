package main

import (
	"errors"
	"log"
	"time"

	"github.com/jroimartin/gocui"
)

func	checkDimensions(mY int, mX int) error {

	if mY < 10 || mX < 10 {
		return errors.New("window dimensions not in bounds")
	}
	return nil
}

func	initGui() (*gocui.Gui, error) {

	g, err := gocui.NewGui(gocui.OutputNormal)
	if err != nil {
		return nil, err
	}
	g.Cursor = true
	g.Mouse = true
	return g, nil
}

func	quit(g *gocui.Gui, v *gocui.View) error {

	return gocui.ErrQuit
}

func	cursorDown(g *gocui.Gui, v *gocui.View) error {

	if v != nil {
		cx, cy := v.Cursor()
		if err := v.SetCursor(cx, cy+1); err != nil {
			ox, oy := v.Origin()
			if err := v.SetOrigin(ox, oy+1); err != nil {
				return err
			}
		}
	}
	return nil
}

func	cursorUp(g *gocui.Gui, v *gocui.View) error {

	if v != nil {
		ox, oy := v.Origin()
		cx, cy := v.Cursor()
		if err := v.SetCursor(cx, cy-1); err != nil && oy > 0 {
			if err := v.SetOrigin(ox, oy-1); err != nil {
				return err
			}
		}
	}
	return nil
}

func	keybindings(g *gocui.Gui) error {
	if err := g.SetKeybinding("", gocui.KeyCtrlC, gocui.ModNone, quit); err != nil {
		log.Panicln(err)
	}
	if err := g.SetKeybinding("", gocui.KeyArrowUp, gocui.ModNone, cursorUp); err != nil {
		log.Panicln(err)
	}
	if err := g.SetKeybinding("", gocui.KeyArrowDown, gocui.ModNone, cursorDown); err != nil {
		log.Panicln(err)
	}
	return nil
}

func	printClients(view *gocui.View) {

	var cliStr string

	view.Clear()
	for _, v := range TargCliGuiG.contents {
		cli := (v).(*Client)
		cliStr = cliStr + cli.hwaddr.String() + "\n"
	}
	_, err := view.Write([]byte(cliStr))
	if err != nil {
		log.Panicln(err)
	}
}

func	clientView(g *gocui.Gui) error {

	mX, mY := g.Size()
	if err := checkDimensions(mX, mY); err != nil {
		return nil
	}
	view, err := g.SetView("clients", 0, 0, mX / 5, mY)
	if err != nil {
		if err != gocui.ErrUnknownView {
			return err
		}
		view.Frame = true
		view.Title = "Clients"
		view.Highlight = true
		view.BgColor = gocui.ColorBlack
		view.FgColor = gocui.ColorYellow
		view.SelBgColor =  gocui.ColorYellow
		view.SelFgColor = gocui.ColorBlack
		if _, err := g.SetCurrentView("clients"); err != nil {
			return err
		}
	}
	printClients(view)
	return nil
}

func	goJamGui(g *gocui.Gui) error {

	tickStart := time.Now()
	if err := clientView(g); err != nil {
		return err
	}
	for time.Since(tickStart) < time.Second {
		packet, err := PktSrcG.NextPacket()
		if err != nil {
			if err.Error() == "Read Error" {
				log.Fatalln("gopacket.PacketSource.NextPacket()", err,
					"\ndevice possibly disconnected or removed from monitor mode")
			}
			if err.Error() != "Timeout Expired" {
				log.Fatalln("gopacket.PacketSource.NextPacket()", err.Error())
			}
		}
		checkComms(TargAPGuiG, TargCliGuiG, WListCliGuiG, packet)
		MonIfaGuiG.DeauthClientsIfPast(time.Second * 5,2, TargAPGuiG)
		MonIfaGuiG.DoAPScanIfPast(time.Minute * 1, WListAPGuiG, TargAPGuiG)
	}
	return nil
}