package main

import (
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/jroimartin/gocui"
)

var (
	ViewInxG = 0
	ViewArrG = []string{ CliViewG, CliWListViewG, APViewG, APWListViewG, AssocViewG }
	BGColorG = gocui.ColorBlack
	FGColorG = gocui.ColorYellow
	APViewG = "APs"
	CliViewG = "Clients"
	StatsViewG = "Stats"
	CliWListViewG = "Whitelisted Clients"
	APWListViewG = "Whitelisted APs"
	AssocViewG = "AP/Client Association"
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
	g.Highlight = true
	//g.Mouse = true
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

func	nextView(g *gocui.Gui, v *gocui.View) error {

	nextIndex := (ViewInxG + 1) % len(ViewArrG)
	name := ViewArrG[nextIndex]

	if _, err := g.SetCurrentView(name); err != nil {
		return err
	}
	ViewInxG = nextIndex
	return nil
}

func getLineFromCursor(v *gocui.View) string {

	var l string
	var err error

	_, cy := v.Cursor()
	if l, err = v.Line(cy); err != nil {
		l = ""
	}
	return strings.TrimSpace(l)
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
	if err := g.SetKeybinding("", gocui.KeyTab, gocui.ModNone, nextView); err != nil {
		log.Panicln(err)
	}
	if err := g.SetKeybinding(CliViewG, gocui.KeySpace, gocui.ModNone, addToCliWList); err != nil {
		log.Panicln(err)
	}
	if err := g.SetKeybinding(APViewG, gocui.KeySpace, gocui.ModNone, addToAPWList); err != nil {
		log.Panicln(err)
	}
	if err := g.SetKeybinding(APWListViewG, gocui.KeySpace, gocui.ModNone, removeFromAPWList); err != nil {
		log.Panicln(err)
	}
	if err := g.SetKeybinding(CliWListViewG, gocui.KeySpace, gocui.ModNone, removeFromCliWList); err != nil {
		log.Panicln(err)
	}
	return nil
}

func	getSSIDMAC(line string) (string, net.HardwareAddr, error) {

	if ok := strings.Contains(line, "|"); ok {
		strs := strings.Split(line, "|")
		ssid := strs[0]
		mac, err := net.ParseMAC(strings.TrimSpace(strs[1]))
		if err != nil {
			return "", nil, errors.New("net.ParseMAC() " + err.Error())
		}
		return ssid, mac, nil
	}
	return "", net.HardwareAddr{}, errors.New("not a ssid/bssid pair")
}

func	removeFromCliWList(g *gocui.Gui, v *gocui.View) error {

	line := getLineFromCursor(v)

	mac, err := net.ParseMAC(line)
	if err == nil {
		CliWListMutexG.Lock()
		CliWListG.Del(mac.String())
		CliWListMutexG.Unlock()
	}
	return nil
}

func	removeFromAPWList(g *gocui.Gui, v *gocui.View) error {

	line := getLineFromCursor(v)

	mac, err := net.ParseMAC(line)
	if err == nil {
		APWListMutexG.Lock()
		APWListG.Del(apKey(mac.String()))
		APWListMutexG.Unlock()
	}
	return nil
}

func	addToCliWList(g *gocui.Gui, v *gocui.View) error {

	line := getLineFromCursor(v)

	mac, err := net.ParseMAC(line)
	if err == nil {
		macStr := mac.String()
		CliWListMutexG.Lock()
		CliWListG.Add(mac.String(), macStr)
		CliWListMutexG.Unlock()
		CliListMutexG.Lock()
		CliListG.Del(macStr)
		CliListMutexG.Unlock()
		for _, v := range APListG.contents {
			ap := (v).(AP)
			if _, ok := ap.GetClient(mac); ok {
				ap.DelClient(mac)
				APListMutexG.Lock()
				APListG.Add(apKey(ap.hwaddr.String()), ap)
				APListMutexG.Unlock()
			}
		}
	}
	return nil
}

func	addToAPWList(g *gocui.Gui, v *gocui.View) error {

	line := getLineFromCursor(v)

	_, mac, err := getSSIDMAC(line)
	if err == nil {
		APWListMutexG.Lock()
		APWListG.Add(apKey(mac.String()), mac.String())
		APWListMutexG.Unlock()
		APListMutexG.Lock()
		APListG.Del(apKey(mac.String()))
		APListMutexG.Unlock()
	}
	return nil
}

func	printStatsView(view *gocui.View) {

	view.Clear()
	monSizeStr := ByteCountIEC(StatsG.nByteMon)
	txSizeStr := ByteCountIEC(StatsG.nByteTx)
	timeStr := sPrintTimeSince(StatsG.sessionStart)
	statStr := fmt.Sprintf("monPk: %d/%s\t\t\t\tpkTx: %d/%s\t\t\t\tnDeauth\\nDissac: %d/%d\t\t\t\t%s",
		StatsG.nPktMon, monSizeStr, StatsG.nPktTx, txSizeStr, StatsG.nDeauth, StatsG.nDisassc, timeStr)
	_, err := view.Write([]byte(statStr))
	if err != nil {
		log.Panicln(err)
	}
}

func	printCliListView(view *gocui.View) {

	view.Clear()
	cliStr := sPrintfCliList(CliListG)
	_, err := view.Write([]byte(cliStr))
	if err != nil {
		log.Panicln(err)
	}
}

func	printCliWListView(view *gocui.View) {

	view.Clear()
	cliStr := sPrintCliWList(CliWListG)
	_, err := view.Write([]byte(cliStr))
	if err != nil {
		log.Panicln(err)
	}
}

func	printAPListView(view *gocui.View) {

	view.Clear()
	apStr := sPrintAPList(APListG)
	_, err := view.Write([]byte(apStr))
	if err != nil {
		log.Panicln(err)
	}
}

func	printAPWListView(view *gocui.View) {

	view.Clear()
	apStr := sPrintAPWList(APWListG)
	_, err := view.Write([]byte(apStr))
	if err != nil {
		log.Panicln(err)
	}
}

func	printAssociationView(view *gocui.View) {

	view.Clear()
	assocStr := sPrintAssociation(APListG, true)
	_, err := view.Write([]byte(assocStr))
	if err != nil {
		log.Panicln(err)
	}
}

func	statsView(g *gocui.Gui) error {

	mX, mY := g.Size()

	if err := checkDimensions(mX, mY); err != nil {
		return nil
	}
	view, err := g.SetView(StatsViewG, 0, 0, mX, 2)
	if err != nil {
		if err != gocui.ErrUnknownView {
			return err
		}
		view.Frame = true
		view.Title = StatsViewG
		view.Highlight = true
		view.BgColor = BGColorG
		view.FgColor = FGColorG
		view.SelBgColor = BGColorG
		view.SelFgColor = FGColorG
		if _, err := g.SetCurrentView(CliViewG); err != nil {
			return err
		}
	}
	printStatsView(view)
	return nil
}

func	cliView(g *gocui.Gui) error {

	mX, mY := g.Size()

	if err := checkDimensions(mX, mY); err != nil {
		return nil
	}
	view, err := g.SetView(CliViewG, 0, 2 + 1, mX / 6, mY / 2)
	if err != nil {
		if err != gocui.ErrUnknownView {
			return err
		}
		view.Frame = true
		view.Title = CliViewG
		view.Highlight = true
		view.BgColor = BGColorG
		view.FgColor = FGColorG
		view.SelBgColor = BGColorG
		view.SelFgColor = FGColorG
		if _, err := g.SetCurrentView(CliViewG); err != nil {
			return err
		}
	}
	printCliListView(view)
	return nil
}

func	cliWListView(g *gocui.Gui) error {

	mX, mY := g.Size()

	if err := checkDimensions(mX, mY); err != nil {
		return nil
	}
	view, err := g.SetView(CliWListViewG, 0, mY / 2, mX / 6, mY)
	if err != nil {
		if err != gocui.ErrUnknownView {
			return err
		}
		view.Frame = true
		view.Title = CliWListViewG
		view.Highlight = true
		view.BgColor = BGColorG
		view.FgColor = FGColorG
		view.SelBgColor = BGColorG
		view.SelFgColor = FGColorG
	}
	printCliWListView(view)
	return nil
}

func	apView(g *gocui.Gui) error {

	mX, mY := g.Size()

	if err := checkDimensions(mX, mY); err != nil {
		return nil
	}
	view, err := g.SetView(APViewG,  (mX / 6) + 1, 2 + 1, (mX / 6) * 3, mY / 2)
	if err != nil {
		if err != gocui.ErrUnknownView {
			return err
		}
		view.Frame = true
		view.Title = APViewG
		view.Highlight = true
		view.BgColor = BGColorG
		view.FgColor = FGColorG
		view.SelBgColor = BGColorG
		view.SelFgColor = FGColorG
	}
	printAPListView(view)
	return nil
}

func	apWListView(g *gocui.Gui) error {

	mX, mY := g.Size()

	if err := checkDimensions(mX, mY); err != nil {
		return nil
	}
	view, err := g.SetView(APWListViewG, (mX / 6) + 1, mY / 2, (mX / 6) * 3, mY)
	if err != nil {
		if err != gocui.ErrUnknownView {
			return err
		}
		view.Frame = true
		view.Title = APWListViewG
		view.Highlight = true
		view.BgColor = BGColorG
		view.FgColor = FGColorG
		view.SelBgColor = BGColorG
		view.SelFgColor = FGColorG
	}
	printAPWListView(view)
	return nil
}

func	associationView(g *gocui.Gui) error {

	mX, mY := g.Size()

	if err := checkDimensions(mX, mY); err != nil {
		return nil
	}
	view, err := g.SetView(AssocViewG,  (mX / 6) * 3 + 1, 2 + 1, (mX / 6) * 6, mY)
	if err != nil {
		if err != gocui.ErrUnknownView {
			return err
		}
		view.Frame = true
		view.Title = AssocViewG
		view.Highlight = true
		view.BgColor = BGColorG
		view.FgColor = FGColorG
		view.SelBgColor = BGColorG
		view.SelFgColor = FGColorG
	}
	printAssociationView(view)
	return nil
}

func	updateViews(t time.Time) {

	views := []string {
		AssocViewG, APViewG,
		APWListViewG, CliViewG,
		CliWListViewG, StatsViewG,
	}
	funcs := []func(view *gocui.View) {
		printAssociationView, printAPListView,
		printAPWListView, printCliListView,
		printCliWListView, printStatsView,
	}

	go GuiG.Update(
		func(g *gocui.Gui) error {
			for i := 0; i < len(views); i++ {
				v, err := g.View(views[i])
				if err != nil {
					log.Panicln("goCui.Gui.View()", err)
				}
				funcs[i](v)
			}
			return nil
		})
}

func	doEvery(d time.Duration, f func(time.Time)) {

	for x := range time.Tick(d) {
		if QuitG {
			break
		}
		f(x)
	}
}

func	goJamGui(g *gocui.Gui) error {

	if err := cliView(g); err != nil {
		return err
	}
	if err := cliWListView(g); err != nil {
		return err
	}
	if err := apView(g); err != nil {
		return err
	}
	if err := apWListView(g); err != nil {
		return err
	}
	if err := associationView(g); err != nil {
		return err
	}
	if err := statsView(g); err != nil {
		return err
	}
	return nil
}