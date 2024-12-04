package main

import (
	"encoding/base64"
	"net/http"
	"net/url"
	"testing"
)

func TestWireGuardViaHttpProxy(t *testing.T) {
	const saseConfig = `
[Interface]
Address = 10.255.240.32
DNS = 10.255.240.1
PrivateKey = gGnCwagYqJMTWD1cPuqD4JobgXa0128U+/whiP86UGU=
ListenPort = 8000

[Peer]\nAllowedIPs = 10.255.240.0/24, 0.0.0.0/0
PublicKey = 8o54P/m42zYYkMEhyTevws+/y7LNmBpTxXE8VyyDd0c=
Endpoint = 67.55.94.84:8055
`

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

	// Add basic auth to the request using "Proxy-Authorization" header
	auth := username + ":" + password
	proxyAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte(auth))

	transport := &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
		ProxyConnectHeader: http.Header{
			"Proxy-Authorization": []string{proxyAuth},
		},
	}

	client := &http.Client{
		Transport: transport,
	}

	req, err := http.NewRequest("GET", "https://example.com/", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Failed to send request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status code 200, got %d", resp.StatusCode)
	}

	wgTurnOff(handle)
	t.Logf("WireGuard proxy turned off")
	// wait indefinitely
	select {}
}
