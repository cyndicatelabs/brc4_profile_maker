package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/cyndicatelabs/brc4_profile_maker/burp"
	"github.com/cyndicatelabs/brc4_profile_maker/utils"
	"github.com/fatih/color"
	"github.com/jroimartin/gocui"
)

var (
	ActiveView             string
	SelectedIndex          int
	MethodFilter           FilteringState
	HostFilter             FilteringState
	MimeFilter             FilteringState
	SelectedRequestsFilter FilteringState

	BurpFilePath string
	BurpLog      *burp.BurpLog

	C2TemplateFile    string = "./resources/brc4_template.json"
	OutputProfileFile string = "output.json"

	MainRequest   int
	MainResponse  int
	EmptyResponse int

	RequestInsertPos  int
	ResponseInsertPos int

	TopView       string = "top"
	ReqHeaderView string = "reqHeaders"
	ReqBodyView   string = "reqBody"
	ResHeaderView string = "resHeaders"
	ResBodyView   string = "resBody"

	WroteToFile bool
	C2Uri       []string
)

// FilteringState holds the state for each filter type.
type FilteringState struct {
	Enabled       bool
	ListEnabled   bool
	SelectedIndex int
	Values        []string
}

type BRC4C2Profile struct {
	RequestHeaders  map[string]string `json:"request_headers"`
	ResponseHeaders map[string]string `json:"response_headers"`
	Prepend         string            `json:"prepend"`
	PrependResponse string            `json:"prepend_response"`
	Append          string            `json:"append"`
	AppendResponse  string            `json:"append_response"`
	EmptyResponse   string            `json:"empty_response"`
	C2Uri           []string          `json:"c2_uri"`
}

// Toggle adding the selected request URL to the C2 URI list
func toggleC2Uri(g *gocui.Gui, v *gocui.View) error {
	if v != nil && v.Name() == TopView {
		logToDisplay := applyFilters()
		if len(logToDisplay.Items) > 0 && SelectedIndex < len(logToDisplay.Items) {
			item := logToDisplay.Items[SelectedIndex]
			url := burp.ConvertBurpUrlToC2Uri(item)
			if !utils.Contains(C2Uri, url) {
				C2Uri = append(C2Uri, url)
			} else {
				C2Uri = utils.Remove(C2Uri, url)
			}
		}
	}
	return nil
	// return refresh(g)
}

// applyFilters applies all active filters to the Burp log.
func applyFilters() *burp.BurpLog {
	currentFilteredLog := BurpLog

	if MethodFilter.Enabled && MethodFilter.SelectedIndex > 0 && MethodFilter.SelectedIndex < len(MethodFilter.Values) {
		currentFilteredLog = burp.FilterLog(currentFilteredLog, func(item burp.BurpItem, value string) bool {
			return item.Method == value
		}, MethodFilter.Values[MethodFilter.SelectedIndex])
	}
	if HostFilter.Enabled && HostFilter.SelectedIndex > 0 && HostFilter.SelectedIndex < len(HostFilter.Values) {
		currentFilteredLog = burp.FilterLog(currentFilteredLog, func(item burp.BurpItem, value string) bool {
			return strings.Contains(item.URL, value)
		}, HostFilter.Values[HostFilter.SelectedIndex])
	}
	if MimeFilter.Enabled && MimeFilter.SelectedIndex > 0 && MimeFilter.SelectedIndex < len(MimeFilter.Values) {
		currentFilteredLog = burp.FilterLog(currentFilteredLog, func(item burp.BurpItem, value string) bool {
			return strings.Contains(item.Mime, value)
		}, MimeFilter.Values[MimeFilter.SelectedIndex])
	}
	return currentFilteredLog
}

// toggleFilterList toggles the visibility of a filter list and ensures focus.
func toggleFilterList(filterToToggle *FilteringState, listNameToToggle string) func(*gocui.Gui, *gocui.View) error {
	return func(g *gocui.Gui, v *gocui.View) error {
		if filterToToggle.ListEnabled && ActiveView == listNameToToggle {
			filterToToggle.ListEnabled = false
			ActiveView = TopView
		} else {
			MethodFilter.ListEnabled = false
			HostFilter.ListEnabled = false
			MimeFilter.ListEnabled = false

			filterToToggle.ListEnabled = true
			ActiveView = listNameToToggle

			filterToToggle.SelectedIndex = 0
			if listGuiView, err := g.View(listNameToToggle); err == nil {
				listGuiView.SetCursor(0, 0)
				listGuiView.SetOrigin(0, 0)
			}
		}

		return refresh(g)
	}
}

func layout(g *gocui.Gui) error {
	maxX, maxY := g.Size()

	// Top view: list of requests, set it to 15% of the screen height
	if v, err := g.SetView(TopView, 0, 0, maxX-1, maxY*12/100); err != nil {
		if err != gocui.ErrUnknownView {
			return err
		}
		v.Highlight = true
		v.SelBgColor = gocui.ColorMagenta
		v.SelFgColor = gocui.ColorBlack
	}
	if topView, _ := g.View(TopView); topView != nil {
		title := " Burp Requests "
		activeFiltersInfo := []string{}
		if MethodFilter.Enabled && MethodFilter.SelectedIndex > 0 && MethodFilter.SelectedIndex < len(MethodFilter.Values) {
			activeFiltersInfo = append(activeFiltersInfo, fmt.Sprintf("Method: %s", MethodFilter.Values[MethodFilter.SelectedIndex]))
		}
		if HostFilter.Enabled && HostFilter.SelectedIndex > 0 && HostFilter.SelectedIndex < len(HostFilter.Values) {
			activeFiltersInfo = append(activeFiltersInfo, fmt.Sprintf("Host: %s", HostFilter.Values[HostFilter.SelectedIndex]))
		}
		if MimeFilter.Enabled && MimeFilter.SelectedIndex > 0 && MimeFilter.SelectedIndex < len(MimeFilter.Values) {
			activeFiltersInfo = append(activeFiltersInfo, fmt.Sprintf("Mime: %s", MimeFilter.Values[MimeFilter.SelectedIndex]))
		}
		if len(activeFiltersInfo) > 0 {
			title = fmt.Sprintf(" Burp Requests (Filters Applied: %s)", strings.Join(activeFiltersInfo, ", "))
		}
		topView.Title = title
		topView.Clear()
		logToDisplay := applyFilters()

		for i, item := range logToDisplay.Items {
			fmt.Fprint(topView, "  ")
			if utils.Contains(C2Uri, burp.ConvertBurpUrlToC2Uri(item)) {
				fmt.Fprint(topView, color.RedString("* "))
			}

			if logToDisplay.Items[i].OriginalIndex == MainRequest {
				fmt.Fprint(topView, color.GreenString("@ "))
			}
			if logToDisplay.Items[i].OriginalIndex == MainResponse {
				fmt.Fprint(topView, color.CyanString("@ "))
			}
			if logToDisplay.Items[i].OriginalIndex == EmptyResponse {
				fmt.Fprint(topView, color.YellowString("@ "))
			}

			fmt.Fprintf(topView, "  %8s   %s %s\n", item.Method, item.URL, item.Mime)
		}
	}

	// Request header panel (left middle), set the panel to the bottom left, 50% high
	if v, err := g.SetView(ReqHeaderView, 0, maxY*14/100, maxX/2-1, maxY*58/100); err != nil {
		if err != gocui.ErrUnknownView {
			return err
		}
		v.Title = " Request Headers "
		v.Wrap = true
		v.Autoscroll = false
		v.Highlight = true
		v.SelBgColor = gocui.ColorMagenta
		v.SelFgColor = gocui.ColorBlack
	}

	// Request body panel (left bottom), set panel to the other bottom left 50%
	if v, err := g.SetView(ReqBodyView, 0, maxY*60/100, maxX/2-1, maxY-4); err != nil {
		if err != gocui.ErrUnknownView {
			return err
		}
		v.Title = " Request Body "
		v.Wrap = true
		v.Autoscroll = false
	}

	// Response header panel (right middle)
	if v, err := g.SetView(ResHeaderView, maxX/2, maxY*14/100, maxX-1, maxY*58/100); err != nil {
		if err != gocui.ErrUnknownView {
			return err
		}
		v.Title = " Response Headers "
		v.Wrap = true
		v.Autoscroll = false
		v.Highlight = true
		v.SelBgColor = gocui.ColorMagenta
		v.SelFgColor = gocui.ColorBlack
	}

	// Response body panel (right bottom)
	if v, err := g.SetView(ResBodyView, maxX/2, maxY*60/100, maxX-1, maxY-4); err != nil {
		if err != gocui.ErrUnknownView {
			return err
		}
		v.Title = " Response Body "
		v.Wrap = true
		v.Autoscroll = false
	}

	// Status bar
	if v, err := g.SetView("status", 0, maxY-3, maxX-1, maxY-1); err != nil {
		if err != gocui.ErrUnknownView {
			return err
		}
		v.Frame = false
		v.BgColor = gocui.ColorMagenta
		v.FgColor = gocui.ColorBlack
	}

	drawFilterList(g, "MethodFilterList", &MethodFilter, maxX, maxY, " Filter by Method ")
	drawFilterList(g, "HostFilterList", &HostFilter, maxX, maxY, " Filter by Host ")
	drawFilterList(g, "MimeFilterList", &MimeFilter, maxX, maxY, " Filter by Mimetype ")

	if !MethodFilter.ListEnabled && !HostFilter.ListEnabled && !MimeFilter.ListEnabled {
		if _, err := g.SetCurrentView(TopView); err != nil && err != gocui.ErrUnknownView {
			// Handle potential error if TopView view doesn't exist
		}
	}

	for _, v := range g.Views() {
		if v.Name() != "status" {
			v.Frame = true
			v.BgColor = gocui.ColorDefault
			v.FgColor = gocui.ColorDefault
			v.SelBgColor = gocui.ColorDefault
			v.SelFgColor = gocui.ColorDefault
		}
	}

	g.SetCurrentView(ActiveView)
	if g.CurrentView().Name() == ReqBodyView || g.CurrentView().Name() == ResBodyView {
		g.Cursor = true
		g.CurrentView().Editable = true
	} else {
		g.Cursor = false
		g.CurrentView().Editable = false
	}
	g.Highlight = true
	// Set the border frame to magenta
	g.CurrentView().Frame = true
	g.CurrentView().SelBgColor = gocui.ColorMagenta
	g.CurrentView().SelFgColor = gocui.ColorBlack
	g.SelFgColor = gocui.ColorMagenta

	updateContent(g)
	updateStatus(g)

	return nil
}

// drawFilterList draws a filter list view.
func drawFilterList(g *gocui.Gui, name string, filter *FilteringState, maxX, maxY int, title string) {
	if filter.ListEnabled {
		x0, y0 := maxX/4, maxY/4
		x1, y1 := (3*maxX/4)-1, (3*maxY/4)-1
		v, err := g.SetView(name, x0, y0, x1, y1)
		if err != nil && err != gocui.ErrUnknownView {
			panic(err)
		}

		g.SelFgColor = gocui.ColorMagenta

		v.Title = title
		v.Highlight = true
		v.SelBgColor = gocui.ColorMagenta
		v.SelFgColor = gocui.ColorBlack
		v.Frame = true

		v.Clear()
		for _, val := range filter.Values {
			fmt.Fprintln(v, " "+val)
		}
		if _, err := g.SetCurrentView(name); err != nil {
			panic(err)
		}
		if _, err := g.SetViewOnTop(name); err != nil {
			panic(err)
		}
		// Restore the cursor position (and thus highlighting)
		if err := v.SetCursor(0, filter.SelectedIndex); err != nil {
			if err := v.SetOrigin(0, filter.SelectedIndex); err != nil {
				// Handle error if necessary
			}
		}
	} else {
		g.DeleteView(name)
	}
}

func toggleHelpFunction(g *gocui.Gui, v *gocui.View) error {
	maxX, maxY := g.Size()
	helpViewName := "helpView"

	// Try to get the help view
	_, err := g.View(helpViewName)

	if err == nil {
		if currentGuiView := g.CurrentView(); currentGuiView != nil && currentGuiView.Name() == helpViewName {
			if _, errSetCurrent := g.SetCurrentView(TopView); errSetCurrent != nil {
				fmt.Printf("Error setting current view to 'top': %v\n", errSetCurrent)
				return errSetCurrent
			}
		}
		return g.DeleteView(helpViewName)
	} else if err == gocui.ErrUnknownView {
		// Help view does not exist, create and display it
		x0, y0 := maxX/4, maxY/4
		x1, y1 := (3*maxX/4)-1, (3*maxY/4)-1

		newHelpView, errSetView := g.SetView(helpViewName, x0, y0, x1, y1)
		if errSetView != nil {
			if errSetView != gocui.ErrUnknownView {
				return errSetView
			}
		}
		newHelpView.Title = " Help "
		newHelpView.Editable = false
		newHelpView.Wrap = true

		fmt.Fprintln(newHelpView, "")
		fmt.Fprintln(newHelpView, "")
		fmt.Fprintln(newHelpView, "\t↑ / ↓ / → / ←   : Navigate within views")
		fmt.Fprintln(newHelpView, "\tTab             : Switch between views")
		fmt.Fprintln(newHelpView, "\tq / Esc         : Quit")
		fmt.Fprintln(newHelpView, "\th / ?           : Toggle help")
		fmt.Fprintln(newHelpView, "")
		fmt.Fprintln(newHelpView, "\tF5              : Toggle method filter")
		fmt.Fprintln(newHelpView, "\tF6              : Toggle host filter")
		fmt.Fprintln(newHelpView, "\tF7              : Toggle mime filter")
		fmt.Fprintln(newHelpView, "")
		fmt.Fprintln(newHelpView, "\tF1  /  u        : Mark URL to be included as a C2 URL (Denoted by a red * in the list)")
		fmt.Fprintln(newHelpView, "\tF2  /  i        : Mark request / response to use (Denoted by a green / cyan @ in the list)")
		fmt.Fprintln(newHelpView, "\tF3  /  b        : Mark as the blank C2 response (Denoted by a yellow @ in the list)")
		fmt.Fprintln(newHelpView, "\tF10 /  s        : Export and save C2 profile to output.json")
		fmt.Fprintln(newHelpView, "")

		if _, err := g.SetViewOnTop(helpViewName); err != nil {
			return err
		}
		if _, err := g.SetCurrentView(helpViewName); err != nil {
			return err
		}
		return nil
	} else {
		return err
	}
}

func updateContent(g *gocui.Gui) error {
	logToDisplay := applyFilters()

	reqHeadersView, _ := g.View(ReqHeaderView)
	reqBodyView, _ := g.View(ReqBodyView)
	resHeadersView, _ := g.View(ResHeaderView)
	resBodyView, _ := g.View(ResBodyView)

	if len(logToDisplay.Items) == 0 {
		if reqHeadersView != nil {
			reqHeadersView.Clear()
			fmt.Fprintln(reqHeadersView, "No request to display based on current filters.")
		}
		if reqBodyView != nil {
			reqBodyView.Clear()
			fmt.Fprintln(reqBodyView, "No request to display based on current filters.")
		}

		if resHeadersView != nil {
			resHeadersView.Clear()
			fmt.Fprintln(resHeadersView, "No response to display based on current filters.")
		}
		if resBodyView != nil {
			resBodyView.Clear()
			fmt.Fprintln(resBodyView, "No response to display based on current filters.")
		}
		return nil
	}

	if SelectedIndex >= len(logToDisplay.Items) {
		SelectedIndex = max(0, len(logToDisplay.Items)-1)
	}
	if SelectedIndex < 0 {
		SelectedIndex = 0
	}

	if reqHeadersView != nil && reqBodyView != nil {
		reqHeadersView.Clear()
		reqBodyView.Clear()
		if SelectedIndex < len(logToDisplay.Items) {
			renderBurpItemInViews(reqHeadersView, reqBodyView, logToDisplay.Items[SelectedIndex].Request, logToDisplay.Items[SelectedIndex].OriginalIndex == MainRequest, false)
		} else {
			fmt.Fprintln(reqHeadersView, "No request to display.")
			fmt.Fprintln(reqBodyView, "No request to display.")
		}
		// reqView.SetOrigin(0, 0)
		reqBodyView.SetOrigin(0, 0)
	}

	if resHeadersView != nil && resBodyView != nil {
		resHeadersView.Clear()
		resBodyView.Clear()
		if SelectedIndex < len(logToDisplay.Items) {
			renderBurpItemInViews(resHeadersView, resBodyView, logToDisplay.Items[SelectedIndex].Response, false, logToDisplay.Items[SelectedIndex].OriginalIndex == MainResponse)
		} else {
			fmt.Fprintln(resHeadersView, "No response to display.")
			fmt.Fprintln(resBodyView, "No response to display.")
		}
		// resView.SetOrigin(0, 0)
		resBodyView.SetOrigin(0, 0)
	}
	return nil
}

func updateStatus(g *gocui.Gui) {
	v, err := g.View("status")
	if err != nil {
		return
	}
	v.Clear()

	filters := []string{}
	if MethodFilter.Enabled && MethodFilter.SelectedIndex > 0 && MethodFilter.SelectedIndex < len(MethodFilter.Values) {
		filters = append(filters, fmt.Sprintf("Method: %s", MethodFilter.Values[MethodFilter.SelectedIndex]))
	}
	if HostFilter.Enabled && HostFilter.SelectedIndex > 0 && HostFilter.SelectedIndex < len(HostFilter.Values) {
		filters = append(filters, fmt.Sprintf("Host: %s", HostFilter.Values[HostFilter.SelectedIndex]))
	}
	if MimeFilter.Enabled && MimeFilter.SelectedIndex > 0 && MimeFilter.SelectedIndex < len(MimeFilter.Values) {
		filters = append(filters, fmt.Sprintf("Mime: %s", MimeFilter.Values[MimeFilter.SelectedIndex]))
	}

	filterStatusText := ""
	if len(filters) > 0 {
		filterStatusText = fmt.Sprintf(" | Filters: %s", strings.Join(filters, ", "))
	}

	logToDisplay := applyFilters()
	reqLen := 0
	resLen := 0
	if len(logToDisplay.Items) > 0 && SelectedIndex >= 0 && SelectedIndex < len(logToDisplay.Items) {
		item := logToDisplay.Items[SelectedIndex]
		reqBytes, _ := base64.StdEncoding.DecodeString(item.Request)
		resBytes, _ := base64.StdEncoding.DecodeString(item.Response)
		reqLen = len(reqBytes)
		resLen = len(resBytes)
	}

	status := fmt.Sprintf("?/h: Help Menu  | Esc/q: Quit | ↑/↓/→/←: Navigate | <tab>: Switch View | Req: %d B Res: %d B%s | Total C2 Urls: %d", reqLen, resLen, filterStatusText, len(C2Uri))

	if WroteToFile {
		status += fmt.Sprintf(" | Wrote to %s", OutputProfileFile)
	}
	fmt.Fprint(v, status)
}

func renderBurpItemInViews(vHeader *gocui.View, vBody *gocui.View, b64 string, isMainRequest bool, isMainResponse bool) {
	data, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		fmt.Fprintf(vHeader, "[decode error: %v]", err)
		return
	}

	content := strings.SplitN(string(data), "\r\n\r\n", 2)
	headers := strings.Split(content[0], "\r\n")
	body := content[1]

	for _, header := range headers {
		fmt.Fprintln(vHeader, header)
	}

	if len(body) > 0 {
		if isMainRequest {
			body = body[:RequestInsertPos] + color.GreenString("*") + body[RequestInsertPos:]
		} else if isMainResponse {
			body = body[:ResponseInsertPos] + color.CyanString("*") + body[ResponseInsertPos:]
		}
		// Bug fix: Remove all \r characters from the body for gocui bug - https://github.com/jroimartin/gocui/issues/51
		fmt.Fprintf(vBody, "%s", strings.Replace(string(body), "\r", "", -1))
	} else {
		fmt.Fprintln(vBody, "[Empty body]")
	}
}

func refresh(g *gocui.Gui) error {
	g.Update(func(gui *gocui.Gui) error {
		gui.DeleteView(TopView)
		gui.DeleteView("req")
		gui.DeleteView("res")
		gui.DeleteView("status")
		gui.DeleteView("MethodFilterList")
		gui.DeleteView("HostFilterList")
		gui.DeleteView("MimeFilterList")
		return layout(gui)
	})
	return nil
}

func cursorDown(g *gocui.Gui, v *gocui.View) error {
	if v != nil && v.Name() == TopView {
		logToDisplay := applyFilters()
		if len(logToDisplay.Items) > 0 && SelectedIndex < len(logToDisplay.Items)-1 {
			SelectedIndex++
			moveCursor(v, 0, 1)
		}
	} else if v != nil && strings.HasSuffix(v.Name(), "FilterList") {
		filter := getFilterStateByName(v.Name())
		if filter != nil && filter.SelectedIndex < len(filter.Values)-1 {
			filter.SelectedIndex++
			moveCursor(v, 0, 1) // Move cursor down in the filter list view
			return refresh(g)
		}
	} else if v != nil && v.Name() == ReqBodyView || v.Name() == ResBodyView {
		moveCursor(v, 0, 1)
	}
	return updateContent(g)
}

func cursorUp(g *gocui.Gui, v *gocui.View) error {
	if v != nil && v.Name() == TopView && SelectedIndex > 0 {
		SelectedIndex--
		moveCursor(v, 0, -1)
	} else if v != nil && strings.HasSuffix(v.Name(), "FilterList") {
		filter := getFilterStateByName(v.Name())
		if filter != nil && filter.SelectedIndex > 0 {
			filter.SelectedIndex--
			moveCursor(v, 0, -1) // Move cursor up in the filter list view
			return refresh(g)
		}
	} else if v != nil && v.Name() == ReqBodyView || v.Name() == ResBodyView || v.Name() == ReqHeaderView || v.Name() == ResHeaderView {
		moveCursor(v, 0, -1)

	}
	return updateContent(g)
}

// moveCursor moves the cursor in a view, adjusting origin if necessary.
func moveCursor(v *gocui.View, dx, dy int) {
	cx, cy := v.Cursor()
	if err := v.SetCursor(cx+dx, cy+dy); err != nil {
		ox, oy := v.Origin()
		if err := v.SetOrigin(ox+dx, oy+dy); err != nil {
			// Handle error if necessary
		}
	}
}

// applyFilterFromList applies the selected filter from a list.
func applyFilterFromList(filter *FilteringState, enableFlag *bool, listEnabledFlag *bool) func(*gocui.Gui, *gocui.View) error {
	return func(g *gocui.Gui, v *gocui.View) error {
		*enableFlag = filter.SelectedIndex > 0
		*listEnabledFlag = false
		SelectedIndex = 0
		if tv, err := g.View(TopView); err == nil {
			tv.SetCursor(0, 0)
			tv.SetOrigin(0, 0)
		}
		return refresh(g)
	}
}

func markAsMainRequest(g *gocui.Gui, v *gocui.View) error {
	logToDisplay := applyFilters()
	if MainRequest == logToDisplay.Items[SelectedIndex].OriginalIndex {
		MainRequest = -1
	} else {
		MainRequest = logToDisplay.Items[SelectedIndex].OriginalIndex
	}
	WroteToFile = false
	return nil
	// return refresh(g)
}

func markAsMainResponse(g *gocui.Gui, v *gocui.View) error {
	if MainResponse == BurpLog.Items[SelectedIndex].OriginalIndex {
		MainResponse = -1
	} else {
		MainResponse = BurpLog.Items[SelectedIndex].OriginalIndex
	}
	WroteToFile = false
	return nil
	// return refresh(g)
}

func markAsEmptyResponse(g *gocui.Gui, v *gocui.View) error {
	if EmptyResponse == BurpLog.Items[SelectedIndex].OriginalIndex {
		EmptyResponse = -1
	} else {
		EmptyResponse = BurpLog.Items[SelectedIndex].OriginalIndex
	}
	WroteToFile = false
	return nil
	// return refresh(g)
}

func exportSelectedToBRC4Profile(g *gocui.Gui, v *gocui.View) error {

	jsonProfile := &BRC4C2Profile{}
	jsonBytes, err := os.ReadFile("./resources/brc4_template.json")
	if err != nil {
		return fmt.Errorf("failed to read template.json: %w", err)
	}

	// We unmarshal into here, as there are fields in a template JSON File we may not know about.
	// But our tool only cares about the options relevent to the requests.
	var allData map[string]any
	if err := json.Unmarshal(jsonBytes, &allData); err != nil {
		return fmt.Errorf("failed to unmarshal JSON: %w", err)
	}

	listenersMap, ok := allData["listeners"].(map[string]any)
	if !ok {
		return fmt.Errorf("'%s' does not contain a 'listeners' object or it's not of the expected type", C2TemplateFile)
	}
	templateListenerUntyped, ok := listenersMap["templateListener"].(map[string]any)
	if !ok {
		return fmt.Errorf("'%s' does not contain a 'templateListener' object under 'listeners', or it's not of the expected type", C2TemplateFile)
	}

	templateListenerBytes, err := json.Marshal(templateListenerUntyped)
	if err != nil {
		return fmt.Errorf("failed to marshal the nested 'templateListener' object: %w", err)
	}
	if err := json.Unmarshal(templateListenerBytes, jsonProfile); err != nil {
		return fmt.Errorf("failed to unmarshal nested 'templateListener' object into BRC4C2Profile struct: %w", err)
	}

	currentLog := applyFilters()

	if MainRequest >= 0 && MainRequest < len(currentLog.Items) {
		reqItem := currentLog.Items[MainRequest]
		reqBytes, err := base64.StdEncoding.DecodeString(reqItem.Request)
		if err != nil {
			return fmt.Errorf("failed to decode request: %w", err)
		}
		reqContent := strings.SplitN(string(reqBytes), "\r\n\r\n", 2)
		if len(reqContent) == 2 {
			reqHeaders := strings.Split(reqContent[0], "\r\n")
			jsonProfile.RequestHeaders = make(map[string]string)
			for _, header := range reqHeaders[1:] {
				parts := strings.SplitN(header, ":", 2)
				if len(parts) == 2 {
					jsonProfile.RequestHeaders[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
				}
			}
			jsonProfile.Prepend = reqContent[1][:RequestInsertPos]
			jsonProfile.Append = reqContent[1][RequestInsertPos:]
		}
	}

	if MainResponse >= 0 && MainResponse < len(currentLog.Items) {
		resItem := currentLog.Items[MainResponse]
		resBytes, err := base64.StdEncoding.DecodeString(resItem.Response)
		if err != nil {
			return fmt.Errorf("failed to decode response: %w", err)
		}
		resContent := strings.SplitN(string(resBytes), "\r\n\r\n", 2)
		if len(resContent) > 1 {
			resHeaders := strings.Split(resContent[0], "\r\n")
			jsonProfile.ResponseHeaders = make(map[string]string)
			for _, header := range resHeaders[1:] {
				parts := strings.SplitN(header, ":", 2)
				if len(parts) == 2 {
					jsonProfile.ResponseHeaders[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
				}
			}
		}
		jsonProfile.PrependResponse = resContent[1][:ResponseInsertPos]
		jsonProfile.AppendResponse = resContent[1][ResponseInsertPos:]
	}

	if EmptyResponse >= 0 && EmptyResponse < len(currentLog.Items) {
		emptyItem := currentLog.Items[EmptyResponse]
		emptyBytes, err := base64.StdEncoding.DecodeString(emptyItem.Response)
		if err != nil {
			return fmt.Errorf("failed to decode empty response: %w", err)
		}
		emptyContent := strings.SplitN(string(emptyBytes), "\r\n\r\n", 2)
		jsonProfile.EmptyResponse = emptyContent[1]
	}

	if len(C2Uri) > 0 {
		jsonProfile.C2Uri = C2Uri
	}

	updatedKnownFieldsBytes, err := json.Marshal(jsonProfile)
	if err != nil {
		return fmt.Errorf("failed to marshal the updated jsonProfile (known fields) to JSON: %w", err)
	}

	var updatedKnownFieldsMap map[string]interface{}
	if err := json.Unmarshal(updatedKnownFieldsBytes, &updatedKnownFieldsMap); err != nil {
		return fmt.Errorf("failed to unmarshal the updated known fields JSON into a map: %w", err)
	}

	for key, value := range updatedKnownFieldsMap {
		templateListenerUntyped[key] = value
	}

	finalJsonBytes, err := json.MarshalIndent(allData, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal the final combined data (with nested updates) to JSON: %w", err)
	}

	if err := os.WriteFile(OutputProfileFile, finalJsonBytes, 0644); err != nil {
		return fmt.Errorf("failed to write output.json: %w", err)
	}

	WroteToFile = true
	updateStatus(g)
	return nil

}

func exitFunc(g *gocui.Gui, v *gocui.View) error {
	return gocui.ErrQuit
}

// getFilterStateByName returns the FilteringState struct based on the view name.
func getFilterStateByName(name string) *FilteringState {
	switch name {
	case "MethodFilterList":
		return &MethodFilter
	case "HostFilterList":
		return &HostFilter
	case "MimeFilterList":
		return &MimeFilter
	case "SelectedRequestsFilter":
		return &SelectedRequestsFilter
	default:
		return nil
	}
}

func main() {

	flags := flag.NewFlagSet("s", flag.ContinueOnError)
	flags.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n\n", os.Args[0])
		flags.PrintDefaults()
	}
	flags.StringVar(&BurpFilePath, "f", "", "Path to the Burp XML file")
	flags.StringVar(&OutputProfileFile, "o", "output.json", "Path to the output JSON file")
	flags.StringVar(&C2TemplateFile, "t", "./resources/brc4_template.json", "Path to the C2 template JSON file")

	flags.Parse(os.Args[1:])

	if BurpFilePath == "" {
		flags.Usage()
		fmt.Println("\nPlease provide the path to the Burp XML file using -f")
		os.Exit(1)
	}

	var err error
	BurpLog, err = burp.ParseBurpXML(BurpFilePath)
	if err != nil {
		fmt.Printf("Failed to parse XML: %v\n", err)
		os.Exit(1)
	}
	if BurpLog == nil || len(BurpLog.Items) == 0 {
		fmt.Println("No items found in Burp log or failed to parse.")
		os.Exit(1)
	}

	rawMethodValues := burp.GetUniqueValues(BurpLog, func(item burp.BurpItem) string { return item.Method })
	MethodFilter.Values = []string{"All"}
	MethodFilter.Values = append(MethodFilter.Values, rawMethodValues...)

	rawHostValues := burp.GetUniqueValues(BurpLog, func(item burp.BurpItem) string {
		parts := strings.Split(item.URL, "/")
		if len(parts) > 2 {
			return parts[2]
		}
		return ""
	})
	HostFilter.Values = []string{"All"}
	HostFilter.Values = append(HostFilter.Values, rawHostValues...)

	rawMimeValues := burp.GetUniqueValues(BurpLog, func(item burp.BurpItem) string { return item.Mime })
	var validMimeValues []string
	for _, mime := range rawMimeValues {
		if mime != "" && strings.ToLower(mime) != "null" { // Filter out empty or "null" mime types
			validMimeValues = append(validMimeValues, mime)
		}
	}
	MimeFilter.Values = []string{"[All MimeTypes]"} // Add "All" option first
	MimeFilter.Values = append(MimeFilter.Values, validMimeValues...)

	g, err := gocui.NewGui(gocui.OutputNormal)
	if err != nil {
		fmt.Println("Failed to initialize GUI:", err)
		os.Exit(1)
	}
	defer g.Close()

	g.Highlight = true
	g.SetManagerFunc(layout)

	mustSetKeybinding := func(viewname string, key []any, mod gocui.Modifier, handler func(*gocui.Gui, *gocui.View) error) {
		for i := range key {
			if err := g.SetKeybinding(viewname, key[i], mod, handler); err != nil {
				panic(err)
			}
		}
	}

	mustSetKeybinding("", []any{gocui.KeyCtrlC, gocui.KeyEsc, 'q'}, gocui.ModNone, exitFunc)
	mustSetKeybinding("", []any{'?', 'h'}, gocui.ModNone, toggleHelpFunction)

	mustSetKeybinding("", []any{gocui.KeyArrowDown}, gocui.ModNone, cursorDown)
	mustSetKeybinding("", []any{gocui.KeyArrowUp}, gocui.ModNone, cursorUp)

	// Keybind tab to toggle view cursor focus between top, req and res. Then set the border color of the active one to purple.
	mustSetKeybinding("", []any{gocui.KeyTab}, gocui.ModNone, func(g *gocui.Gui, v *gocui.View) error {
		currentView := g.CurrentView()
		nextViewName := TopView
		if currentView == nil || currentView.Name() == TopView {
			nextViewName = ReqBodyView
		} else if currentView.Name() == ReqBodyView {
			nextViewName = ResBodyView
		} else if currentView.Name() == ResBodyView {
			nextViewName = TopView
		}
		ActiveView = nextViewName
		return nil
	})

	mustSetKeybinding("", []any{gocui.KeyF5}, gocui.ModNone, toggleFilterList(&MethodFilter, "MethodFilterList"))
	mustSetKeybinding("", []any{gocui.KeyF6}, gocui.ModNone, toggleFilterList(&HostFilter, "HostFilterList"))
	mustSetKeybinding("", []any{gocui.KeyF7}, gocui.ModNone, toggleFilterList(&MimeFilter, "MimeFilterList"))

	mustSetKeybinding(ReqBodyView, []any{'i', gocui.KeyF2}, gocui.ModNone, func(g *gocui.Gui, v *gocui.View) error {
		RequestCursorPosX, RequestCursorPosY := v.Cursor()
		v, _ = g.View(ReqBodyView)
		x, _ := v.Size()
		RequestInsertPos = x*RequestCursorPosY + RequestCursorPosX
		markAsMainRequest(g, v)
		return nil
	})
	mustSetKeybinding(ResBodyView, []any{'i', gocui.KeyF2}, gocui.ModNone, func(g *gocui.Gui, v *gocui.View) error {
		ResponseCursorPosX, ResponseCursorPosY := v.Cursor()
		v, _ = g.View(ResBodyView)
		x, _ := v.Size()
		ResponseInsertPos = x*ResponseCursorPosY + ResponseCursorPosX
		markAsMainResponse(g, v)
		return nil
	})
	mustSetKeybinding("", []any{'b', gocui.KeyF3}, gocui.ModNone, func(g *gocui.Gui, v *gocui.View) error {
		markAsEmptyResponse(g, v)
		return nil
	})

	mustSetKeybinding("", []any{gocui.KeyF1, 'u'}, gocui.ModNone, toggleC2Uri)
	mustSetKeybinding("", []any{'s', gocui.KeyCtrlS, gocui.KeyF10}, gocui.ModNone, exportSelectedToBRC4Profile)

	mustSetKeybinding("MethodFilterList", []any{gocui.KeyEnter}, gocui.ModNone, applyFilterFromList(&MethodFilter, &MethodFilter.Enabled, &MethodFilter.ListEnabled))
	mustSetKeybinding("MethodFilterList", []any{gocui.KeyEsc}, gocui.ModNone, toggleFilterList(&MethodFilter, "MethodFilterList"))

	mustSetKeybinding("HostFilterList", []any{gocui.KeyEnter}, gocui.ModNone, applyFilterFromList(&HostFilter, &HostFilter.Enabled, &HostFilter.ListEnabled))
	mustSetKeybinding("HostFilterList", []any{gocui.KeyEsc}, gocui.ModNone, toggleFilterList(&HostFilter, "HostFilterList"))

	mustSetKeybinding("MimeFilterList", []any{gocui.KeyEnter}, gocui.ModNone, applyFilterFromList(&MimeFilter, &MimeFilter.Enabled, &MimeFilter.ListEnabled))
	mustSetKeybinding("MimeFilterList", []any{gocui.KeyEsc}, gocui.ModNone, toggleFilterList(&MimeFilter, "MimeFilterList"))

	// Set a keybinding for the top view to show only the selected requests, responses, blank response and selected URIs
	// mustSetKeybinding(TopView, []any{'x', gocui.KeyCtrlS}, gocui.ModNone, func(g *gocui.Gui, v *gocui.View) error {
	// 	SelectedRequestsFilter.Enabled = !SelectedRequestsFilter.Enabled
	// 	if SelectedRequestsFilter.Enabled {
	// 		SelectedRequestsFilter.Values = append(SelectedRequestsFilter.Values, burp.FilterSelected(BurpLog, C2Uri, MainRequest, MainResponse, EmptyResponse)...)
	// 	} else {
	// 		SelectedRequestsFilter.Values = []string{}
	// 	}
	// 	return refresh(g)
	// })

	ActiveView = TopView
	SelectedIndex = 0
	MainRequest = -1
	MainResponse = -1
	EmptyResponse = -1

	if err := g.MainLoop(); err != nil && err != gocui.ErrQuit {
		fmt.Println("Error in main loop:", err)
		os.Exit(1)
	}
}
