package burp

import (
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/cyndicatelabs/brc4_profile_maker/utils"
)

type BurpItem struct {
	OriginalIndex int
	URL           string `xml:"url"`
	Host          string `xml:"host"`
	Method        string `xml:"method"`
	Mime          string `xml:"mimetype"`
	Request       string `xml:"request"`
	Response      string `xml:"response"`
}

type BurpLog struct {
	Items []BurpItem `xml:"item"`
}

func ParseBurpXML(filePath string) (*BurpLog, error) {
	xmlFile, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open XML file: %w", err)
	}
	defer xmlFile.Close()

	byteValue, err := io.ReadAll(xmlFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read XML file: %w", err)
	}

	var log BurpLog
	if err := xml.Unmarshal(byteValue, &log); err != nil {
		return nil, fmt.Errorf("failed to unmarshal XML: %w", err)
	}

	for i := range log.Items {
		log.Items[i].OriginalIndex = i
	}

	return &log, nil
}

func ConvertBurpUrlToC2Uri(item BurpItem) string {
	// Convert the Burp URL to a C2 URI format
	url := strings.Split(item.URL, "?")[0]
	url = strings.Replace(url, "https://", "", -1)
	url = strings.Replace(url, "http://", "", -1)
	url = strings.Replace(url, item.Host, "", -1)
	return url
}

func GetUniqueValues(log *BurpLog, extractFunc func(BurpItem) string) []string {
	uniqueValues := make(map[string]struct{})
	for _, item := range log.Items {
		value := extractFunc(item)
		if value != "" {
			uniqueValues[value] = struct{}{}
		}
	}
	result := make([]string, 0, len(uniqueValues))
	for value := range uniqueValues {
		result = append(result, value)
	}
	return result
}

func FilterLog(log *BurpLog, filterFunc func(BurpItem, string) bool, filterValue string) *BurpLog {
	if filterValue == "" || filterValue == "All" {
		return log
	}
	filteredItems := []BurpItem{}
	for _, item := range log.Items {
		if filterFunc(item, filterValue) {
			filteredItems = append(filteredItems, item)
		}
	}
	return &BurpLog{Items: filteredItems}
}

func FilterSelected(log *BurpLog, C2Uri []string, MainReqest int, MainResponse int, EmptyResponse int) *BurpLog {
	// if filterValue == "" || filterValue == "All" {
	// 	return log
	// }
	filteredItems := []BurpItem{}
	for i, item := range log.Items {
		url := ConvertBurpUrlToC2Uri(item)
		if utils.Contains(C2Uri, url) {
			filteredItems = append(filteredItems, item)
		}
		if i == MainReqest || i == MainResponse || i == EmptyResponse {
			filteredItems = append(filteredItems, item)
		}
	}
	return &BurpLog{Items: filteredItems}
}
