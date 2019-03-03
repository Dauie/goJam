package main

import (
	"errors"
	"fmt"
	"log"
	"sort"
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
	return nil
}

func	printCliView(view *gocui.View) {

	var cliStr string
	var cliArr []string

	view.Clear()
	for _, v := range TargCliGuiG.contents {
		cli := (v).(*Client)
		cliArr = append(cliArr, cli.hwaddr.String())
	}
	sort.Strings(cliArr)
	for _, v := range cliArr {
		cliStr = cliStr + v + "\n"
	}
	_, err := view.Write([]byte(cliStr))
	if err != nil {
		log.Panicln(err)
	}
}

func	printCliWListView(view *gocui.View) {

	var cliStr string
	var cliArr []string

	view.Clear()
	for _, v := range WListCliGuiG.contents {
		cli := (v).(string)
		cliArr = append(cliArr, cli)
	}
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
	for _, v := range TargAPGuiG.contents {
		ap := (v).(AP)
		apArr = append(apArr, ap.ssid + " - " + ap.hwaddr.String())
	}
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
	for _, v := range WListCliGuiG.contents {
		ap := (v).(string)
		apArr = append(apArr, ap)
	}
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
	for _, v := range TargAPGuiG.contents {
		ap := (v).(AP)
		apStr := fmt.Sprintf("%s - %s\n", ap.ssid, ap.hwaddr.String())
		var cliArr []string
		for _, v := range ap.clients {
			cliArr = append(cliArr, v.hwaddr.String())
		}
		sort.Strings(cliArr)
		for _, v := range cliArr {
			apStr = apStr + v + "\n"
		}
		assocArr = append(assocArr, apStr)
	}
	sort.Strings(assocArr)
	for _, v := range assocArr {
		assocStr = assocStr + v + "\n"
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

	// Association View
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
	// AP View
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
	// AP Whitelist View
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
	// Client View
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
	// Client Whitelist View
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