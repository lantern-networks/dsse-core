module github.com/lantern-networks/dsse-core/egress-broker

go 1.26.0

require golang.org/x/net v0.59.0

require (
	golang.org/x/sys v0.48.0 // indirect
	golang.org/x/text v0.42.0 // indirect
)

// The egress block list lives in dsse-core/swg — one definition for the whole product. The broker imports
// it so the SIDECAR topology gets the same peer check the embedded one does; without it, only the embedded
// build would close the gap and the deployed topology would keep the weaker guard.
require github.com/lantern-networks/dsse-core v0.0.0

replace github.com/lantern-networks/dsse-core => ..
