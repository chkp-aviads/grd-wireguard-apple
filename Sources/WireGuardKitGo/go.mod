module wireguard-apple

go 1.23.1

toolchain go1.23.5

require (
	golang.org/x/sys v0.32.0
	golang.zx2c4.com/wireguard v0.0.20250817
	tun2socks v1.1.1
)

require (
	github.com/eycorsican/go-tun2socks v1.16.11 // indirect
	github.com/google/btree v1.1.3 // indirect
	github.com/nomad-software/vend v1.0.3 // indirect
	golang.org/x/crypto v0.37.0 // indirect
	golang.org/x/net v0.39.0 // indirect
	golang.org/x/time v0.11.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect

)

replace tun2socks => github.com/chkp-aviads/apple-gotun2socks-library v1.1.1
replace golang.zx2c4.com/wireguard => github.com/chkp-aviads/wireguard-go v0.0.20250817
