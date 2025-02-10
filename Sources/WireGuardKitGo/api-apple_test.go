package main

import (
	// "context"
	"encoding/base64"
	"net"

	// "net"
	"net/http"
	"net/url"
	"testing"
	"time"
	// "golang.org/x/net/proxy"
)

func TestWireGuardViaHttpProxy(t *testing.T) {
	const saseConfig = `
[Interface]
Address = 192.168.6.60/32
DNS = 1.1.1.1,8.8.8.8
PrivateKey = 4D4bqTEQVDLkhc8TrgHySx87GftW7iUYTreNpDYhT1U=
[Peer]
publickey=Q8c8F4MGGpLUeQ0YIUhYsxh+QVU68stU96k7BjgJ+RY=
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = hk1.vpnjantit.com:1024
`

	username := "test"
	password := "test"

	handle := StartWireGuardProxy(saseConfig, "127.0.0.1:9092", username, password)
	if handle == -1 {
		t.Fatalf("Failed to start wireguard proxy")
	}

	// proxy address
	proxyAddr := "127.0.0.1:9092"
	// proxyAuth := &proxy.Auth{
	// 	User:     username,
	// 	Password: password,
	// }

	// Create a proxy URL
	proxyURL, err := url.Parse("http://" + proxyAddr)
	if err != nil {
		t.Fatalf("Failed to parse proxy URL: %v", err)
	}

	// Create a custom transport with the proxy
	httpTransport := &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
	}

	// Create an HTTP client with the custom transport
	client := &http.Client{
		Transport: httpTransport,
		Timeout:   10 * time.Second,
	}

	// Create a request
	req, err := http.NewRequest("GET", "http://example.com", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	// Add Proxy-Authorization header
	auth := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
	req.Header.Add("Proxy-Authorization", "Basic "+auth)

	// Send the request
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Failed to send GET request: %v", err)
	}
	// // Create a SOCKS5 dialer
	// dialer, err := proxy.SOCKS5("tcp", proxyAddr, proxyAuth, proxy.Direct)
	// if err != nil {
	// 	t.Fatalf("Failed to create SOCKS5 dialer: %v", err)
	// }

	// // Create an HTTP client that uses the SOCKS5 proxy
	// httpTransport := &http.Transport{
	// 	DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
	// 		return dialer.Dial(network, addr)
	// 	},
	// }
	// client := &http.Client{
	// 	Transport: httpTransport,
	// 	Timeout:   10 * time.Second,
	// }

	// Send GET request to example.com
	// resp, err := client.Get("http://example.com")
	// if err != nil {
	// 	t.Fatalf("Failed to send GET request: %v", err)
	// }
	// defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status code 200, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	// if StartHealthCheckServer(handle, "127.0.0.1:9093") < 0 {
	// 	t.Fatalf("Failed to start health check server")
	// }

	// // Wait 10 seconds
	// time.Sleep(10 * time.Second)

	// // Query health check server
	// pingreq, err := http.NewRequest("GET", "http://127.0.0.1:9093/readyz", nil)
	// if err != nil {
	// 	t.Fatalf("Failed to create request: %v", err)
	// }
	// // Send request and check response
	// pingresp, err := http.DefaultClient.Do(pingreq)
	// if err != nil {
	// 	t.Fatalf("Failed to send request: %v", err)
	// }
	// defer pingresp.Body.Close()
	// if pingresp.StatusCode != http.StatusOK {
	// 	// t.Fatalf("Expected status code 200, got %d", resp.StatusCode)
	// }

	// wgSuspendHealthCheckPings(handle)

	// Establish a plain TCP connection to the proxy address
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("Failed to establish TCP connection to proxy: %v", err)
	}

	t.Logf("TCP connection established to proxy")

	// Check if the connection is open
	if !checkConnection(conn) {
		t.Fatalf("TCP connection should be open, but it is closed")
	}

	// Wait a moment to ensure the proxy has shut down
	time.Sleep(5 * time.Second)

	// time.Sleep(2 * time.Second)
	wgTurnOff(handle)
	t.Logf("WireGuard proxy turned off")

	// Wait a moment to ensure the proxy has shut down
	time.Sleep(2 * time.Second)

	// Check if the connection is closed
	if checkConnection(conn) {
		t.Fatalf("TCP connection should be closed, but it is still open")
	}

	// // Check if the TCP connection is disconnected
	// _, err = conn.Write([]byte("test"))
	// if err == nil {
	// 	t.Fatalf("Expected TCP connection to be disconnected, but it is still active")
	// }

	t.Logf("TCP connection was successfully disconnected after turning off the proxy: %v", err)

	// wait indefinitely
	select {}
}

// Function to check if the connection is open
func checkConnection(conn net.Conn) bool {
	conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	buf := make([]byte, 1)
	_, err := conn.Read(buf)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return true // Connection is open
		}
		return false // Connection is closed
	}
	return true // Connection is open
}
