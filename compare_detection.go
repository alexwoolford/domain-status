package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	wappalyzer "github.com/projectdiscovery/wappalyzergo"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <url>\n", os.Args[0])
		os.Exit(1)
	}

	url := os.Args[1]
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		url = "https://" + url
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	resp, err := client.Get(url)
	if err != nil {
		log.Fatalf("Failed to fetch %s: %v", url, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Failed to read body: %v", err)
	}

	wappalyzerClient, err := wappalyzer.New()
	if err != nil {
		log.Fatalf("Failed to create wappalyzer client: %v", err)
	}

	fingerprints := wappalyzerClient.Fingerprint(resp.Header, body)

	// Sort technologies for consistent output
	techs := make([]string, 0, len(fingerprints))
	for tech := range fingerprints {
		techs = append(techs, tech)
	}
	sort.Strings(techs)

	// Output as JSON array for easy parsing
	jsonBytes, _ := json.Marshal(techs)
	fmt.Println(string(jsonBytes))
}
