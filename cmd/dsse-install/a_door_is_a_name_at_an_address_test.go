package main

import "testing"

// ★★★ A PAIR IS ONE NAME AT TWO ADDRESSES, AND THE CHECK COULD NOT BE TOLD (2026-08-28, measured on the first
// deployment whose two doors were both on 443).
//
// Every mouth of this product is 443 and the planes are separated by NAME, so a doorway pair is necessarily
// two addresses answering to the same name. Given the second door as an address, the check dialled
// https://<address>, and the certificate — which carries names — did not match:
//
//	1 of 2 front door(s) lead to this deployment
//
// on a deployment where both doors answered 200 to the name. The check was right about what it measured: an
// address not in the certificate is not a door a device can use. It had no way to be told the true shape.
func TestADoorMayBeWrittenAsANameAtAnAddress(t *testing.T) {
	for _, c := range []struct{ in, dial, name string }{
		{"https://agents.dsse.lab@54.64.173.77", "https://54.64.173.77", "agents.dsse.lab"},
		{"https://agents.dsse.lab", "https://agents.dsse.lab", ""},
		{"https://agents.dsse.lab/", "https://agents.dsse.lab", ""},
		{"agents.dsse.lab@10.0.0.2", "https://10.0.0.2", "agents.dsse.lab"},
	} {
		dial, name := frontDoorTarget(c.in)
		if dial != c.dial || name != c.name {
			t.Errorf("%q -> dial %q name %q, wanted dial %q name %q", c.in, dial, name, c.dial, c.name)
		}
	}
}

// ★ AND A PLAIN ADDRESS IS STILL A PLAIN ADDRESS. Reading every door as a name would silently stop verifying
// the certificate against what was actually dialled, which is the property this check exists for.
func TestAPlainDoorIsUnchanged(t *testing.T) {
	dial, name := frontDoorTarget("https://54.64.173.77")
	if dial != "https://54.64.173.77" || name != "" {
		t.Errorf("a plain address was rewritten: dial %q name %q", dial, name)
	}
}
