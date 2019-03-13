package main

import (
	"errors"
	"fmt"
	"log"
	"net"
	"sort"
	"strings"
	"sync"
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

func	getSSIDMACPair(line string) (string, net.HardwareAddr, error) {

	line = strings.TrimSpace(line)

	if len(line) < MacStrLen {
		return "", net.HardwareAddr{}, errors.New("string too short")
	}
	if ok := strings.Contains(line, "-"); ok {
		strs := strings.Split(line, "-")
		ssid := strings.TrimSpace(string(strs[0]))
		mac, err := net.ParseMAC(strings.TrimSpace(string(strs[1])))
		if err != nil {
			return "", nil, errors.New("net.ParseMAC() " + err.Error())
		}
		return ssid, mac, nil
	} else {
		mac, err := net.ParseMAC(strings.TrimSpace(line))
		if err != nil {
			return "", nil, errors.New("net.ParseMAC() " + err.Error())
		}
		return "", mac, nil
	}
}

func	removeFromCliWList(g *gocui.Gui, v *gocui.View) error{

	line := getLineFromCursor(v)

	if len(line) < MacStrLen {
		return nil
	}
	CliWListMutexG.Lock()
	CliWListG.Del(line)
	CliWListMutexG.Unlock()
	return nil
}

func	removeFromAPWList(g *gocui.Gui, v *gocui.View) error {

	line := getLineFromCursor(v)

	_, mac, err := getSSIDMACPair(line)
	if err != nil {
		if err.Error() == "string too short" {
			return nil
		}
		return errors.New("getSSIDMACPair() " + err.Error())
	}
	APWListMutexG.Lock()
	APWListG.Del(mac.String()[:16])
	APWListMutexG.Unlock()
	return nil
}

func	addToCliWList(g *gocui.Gui, v *gocui.View) error {

	line := getLineFromCursor(v)
	line = strings.Split(line, "-")[0]
	line = strings.TrimSpace(line)
	if len(line) < MacStrLen {
		return nil
	}
	CliWListG.Add(line, line)
	CliListG.Del(line)
	for _, v := range APListG.contents {
		ap := (v).(AP)
		hwaddr, err := net.ParseMAC(line)
		if err != nil {
			return errors.New("net.ParseMAC() " + err.Error())
		}
		if _, ok := ap.GetClient(hwaddr); ok {
			ap.DelClient(hwaddr)
			ApListMutexG.Lock()
			APListG.Add(ap.hwaddr.String()[:16], ap)
			ApListMutexG.Unlock()
		}
	}
	return nil
}

func	addToAPWList(g *gocui.Gui, v *gocui.View) error {

	line := getLineFromCursor(v)

	_, mac, err := getSSIDMACPair(line)
	if err != nil {
		if err.Error() == "string too short" {
			return nil
		}
		return errors.New("getSSIDMACPair() " + err.Error())
	}
	APWListMutexG.Lock()
	APWListG.Add(mac.String()[:16], line)
	APWListMutexG.Unlock()
	ApListMutexG.Lock()
	APListG.Del(mac.String()[:16])
	ApListMutexG.Unlock()
	return nil
}

func	printCliView(view *gocui.View) {

	var cliStr string
	var cliArr []string

	view.Clear()
	CliListMutexG.Lock()
	for _, v := range CliListG.contents {
		cli := (v).(*Client)
		c := fmt.Sprintf("%s - %d\n", cli.hwaddr.String(), cli.nDeauth)
		cliArr = append(cliArr, c)
	}
	CliListMutexG.Unlock()
	sort.Strings(cliArr)
	for _, v := range cliArr {
		cliStr = cliStr + v
	}
	_, err := view.Write([]byte(cliStr))
	if err != nil {
		log.Panicln(err)
	}
}

func	printCliWListView(view *gocui.View) {

	var cliStr	string
	var cliArr		[]string

	view.Clear()
	CliWListMutexG.Lock()
	for _, v := range CliWListG.contents {
		cli := (v).(string)
		cliArr = append(cliArr, cli)
	}
	CliWListMutexG.Unlock()
	sort.Strings(cliArr)
	for _, v := range cliArr {
		cliStr = cliStr + v + "\n"
	}
	_, err := view.Write([]byte(cliStr))
	if err != nil {
		log.Panicln(err)
	}
}

func	printAPs(view *gocui.View) {

	var apStr	string
	var apArr	[]string

	view.Clear()
	ApListMutexG.Lock()
	for _, v := range APListG.contents {
		ap := (v).(AP)
		apArr = append(apArr, ap.ssid + " - " + ap.hwaddr.String())
	}
	ApListMutexG.Unlock()
	sort.Strings(apArr)
	for _, v := range apArr {
		apStr = apStr + v + "\n"
	}
	_, err := view.Write([]byte(apStr))
	if err != nil {
		log.Panicln(err)
	}
}

func	printAPWListView(view *gocui.View) {

	var apStr string
	var apArr []string

	view.Clear()
	APWListMutexG.Lock()
	for _, v := range APWListG.contents {
		ap := (v).(string)
		apArr = append(apArr, ap)
	}
	APWListMutexG.Unlock()
	sort.Strings(apArr)
	for _, v := range apArr {
		apStr = apStr + v + "\n"
	}
	_, err := view.Write([]byte(apStr))
	if err != nil {
		log.Panicln(err)
	}
}

func	printAssociation(view *gocui.View) {

	var assocStr	string
	var assocArr	[]string

	view.Clear()
	ApListMutexG.Lock()
	for _, v := range APListG.contents {
		ap := (v).(AP)
		apStr := fmt.Sprintf("%s - %s - %dMhz\n", ap.ssid, ap.hwaddr.String(), ap.freq)
		var cliArr []string
		for _, v := range ap.clients {
			c := fmt.Sprintf("\t\t%s - %d\n", v.hwaddr.String(), v.nDeauth)
			cliArr = append(cliArr, c)
		}
		sort.Strings(cliArr)
		for _, v := range cliArr {
			apStr = apStr + v
		}
		assocArr = append(assocArr, apStr + "\n")
	}
	ApListMutexG.Unlock()
	sort.Strings(assocArr)
	for _, v := range assocArr {
		assocStr = assocStr + v
	}
	_, err := view.Write([]byte(assocStr))
	if err != nil {
		log.Panicln(err)
	}
}

func	cliView(g *gocui.Gui) error {

	mX, mY := g.Size()

	if err := checkDimensions(mX, mY); err != nil {
		return nil
	}
	view, err := g.SetView(CliViewG, 0, 0, mX / 6, mY / 2)
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
	printCliView(view)
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
	view, err := g.SetView(APViewG,  (mX / 6) + 1, 0, (mX / 6) * 3, mY / 2)
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
	printAPs(view)
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
	view, err := g.SetView(AssocViewG,  (mX / 6) * 3 + 1, 0, (mX / 6) * 6, mY)
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
	printAssociation(view)
	return nil
}

func	updateViews(t time.Time) {

	var wg sync.WaitGroup

	// 1. Association View
	wg.Add(5)
	go GuiG.Update(
		func(g *gocui.Gui) error {
			v, err := g.View(AssocViewG)
			if err != nil {
				log.Panicln("goCui.Gui.View()", err)
			}
			v.Clear()
			printAssociation(v)
			wg.Done()
			return nil
		})
	// 2. AP View
	go GuiG.Update(
		func(g *gocui.Gui) error {
			v, err := g.View(APViewG)
			if err != nil {
				log.Panicln("goCui.Gui.View()", err)
			}
			v.Clear()
			printAPs(v)
			wg.Done()
			return nil
		})
	// 3. AP Whitelist View
	go GuiG.Update(
		func(g *gocui.Gui) error {
			v, err := g.View(APWListViewG)
			if err != nil {
				log.Panicln("goCui.Gui.View()", err)
			}
			v.Clear()
			printAPWListView(v)
			wg.Done()
			return nil
		})
	// 4. Client View
	go GuiG.Update(
		func(g *gocui.Gui) error {
			v, err := g.View(CliViewG)
			if err != nil {
				log.Panicln("goCui.Gui.View()", err)
			}
			v.Clear()
			printCliView(v)
			wg.Done()
			return nil
	})
	// 5. Client Whitelist View
	go GuiG.Update(
		func(g *gocui.Gui) error {
			v, err := g.View(CliWListViewG)
			if err != nil {
				log.Panicln("goCui.Gui.View()", err)
			}
			v.Clear()
			printCliWListView(v)
			wg.Done()
			return nil
		})
	wg.Wait()
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
	return nil
}