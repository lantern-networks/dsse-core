package main

import "flag"

// Keep the optional signed-profile input outside main.go's frozen flag block.
var networkExtensionExactHTTPSPassthrough = flag.String(
	"network-extension-exact-https-passthrough-endpoints-json", "",
	"optional JSON array of dedicated HTTPS IdP {hostname,addresses} pairs to issue in signed Mac install profiles; each flow still requires exact name, current DNS address and TCP/443; empty means no exception",
)
