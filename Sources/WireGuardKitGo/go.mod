module wireguard-apple

go 1.23.1

toolchain go1.23.5

require (
	golang.org/x/sys v0.32.0
	golang.zx2c4.com/wireguard v0.0.0-20231211153847-12269c276173
	tun2socks v0.0.0
	wireproxy v0.0.0
)

require (
	github.com/MakeNowJust/heredoc/v2 v2.0.1 // indirect
	github.com/eycorsican/go-tun2socks v1.16.11 // indirect
	github.com/go-ini/ini v1.67.0 // indirect
	github.com/google/btree v1.1.3 // indirect
	github.com/songgao/water v0.0.0-20200317203138-2b4b6d7c09d8 // indirect
	github.com/things-go/go-socks5 v0.0.5 // indirect
	golang.org/x/crypto v0.37.0 // indirect
	golang.org/x/net v0.39.0 // indirect
	golang.org/x/time v0.11.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
	gvisor.dev/gvisor v0.0.0-20230927004350-cbd86285d259 // indirect

)

replace (
	tun2socks => /Users/aviads/Documents/git/ONPNGPOC/apple-gotun2socks-library
	wireproxy => /Users/aviads/Documents/git/ONPNGPOC/GuardianWireGuard/wireguard/Sources/WireGuardKitGo/wireproxy
)
