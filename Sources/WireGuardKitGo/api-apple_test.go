package main

import (
	"encoding/base64"
	"net/http"
	"net/url"
	"testing"
)

func TestWireGuardViaHttpProxy(t *testing.T) {
	const saseConfig = `enter wireguard ini config here`
	
	username := "test"
	password := "test"

	handle := StartWireGuardProxy(saseConfig, "127.0.0.1:9092", username, password)
	if handle == -1 {
		t.Fatalf("Failed to start wireguard proxy")
	}

	proxyURL, err := url.Parse("http://127.0.0.1:9092")
	if err != nil {
		t.Fatalf("Failed to parse proxy URL: %v", err)
	}

	transport := &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
	}

	client := &http.Client{
		Transport: transport,
	}

	req, err := http.NewRequest("GET", "http://example.com/", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	// Add basic auth to the request using "Proxy-Authorization" header
	auth := username + ":" + password
	req.Header.Add("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(auth)))

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Failed to send request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status code 200, got %d", resp.StatusCode)
	}
}
