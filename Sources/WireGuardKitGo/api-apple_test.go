package main

import (
	"encoding/base64"
	"net/http"
	"net/url"
	"testing"
	"time"
)

func TestWireGuardViaHttpProxy(t *testing.T) {
	const saseConfig = `
[Interface]
ListenPort = 8000
DNS = 10.255.240.1
CheckAlive = 10.255.240.1
CheckAliveInterval = 3
PrivateKey = +DOLuVSmTq7QMWHhVvSzT5pInU5lF+XY618M3cFUcXc=
Address = 10.255.240.18

[Peer]
PublicKey = g9iZftABtEzok6HUBuYwmcHF+tuTUk6Gzlj3FM+9TXA=
AllowedIPs = 10.255.240.0/24, 0.0.0.0/0
Endpoint = 67.55.94.85:8055
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

	if StartHealthCheckServer(handle, "127.0.0.1:9093") < 0 {
		t.Fatalf("Failed to start health check server")
	}

	// Wait 10 seconds
	time.Sleep(10 * time.Second)

	// Query health check server
	pingreq, err := http.NewRequest("GET", "http://127.0.0.1:9093/readyz", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	// Send request and check response
	pingresp, err := http.DefaultClient.Do(pingreq)
	if err != nil {
		t.Fatalf("Failed to send request: %v", err)
	}
	defer pingresp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status code 200, got %d", resp.StatusCode)
	}

	// wgTurnOff(handle)
	t.Logf("WireGuard proxy turned off")
	// wait indefinitely
	select {}
}
