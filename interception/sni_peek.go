package interception

import (
	"errors"
	"io"
)

// The basis for deciding interception from the SNI. Chrome resolves DNS itself and connects to an IP —
// IPv6 especially — so the route.Host the network extension hands over is an ADDRESS and every hostname match
// misses. A TLS ClientHello's SNI is a hostname even on an IP connection, so reading it makes the
// intercept/bypass decision hold for those flows too. This file extracts the SNI from the ClientHello and
// buffers the raw bytes it read while doing so, so whatever comes next — interception or a raw forward — can
// replay them.

var errNotClientHello = errors.New("not a TLS ClientHello record")

const maxClientHelloRecord = 16640 // one TLS record (16 KiB) plus room for the header

// PeekClientHelloSNI reads the first TLS handshake record (the ClientHello) from r and returns its SNI
// (server_name, host_name). The raw bytes it read come back in buffered, so the caller can replay them
// downstream or upstream whether it intercepts or raw-forwards. A missing or unparseable SNI is NOT an error:
// it returns buffered and an empty SNI, so the caller chooses its own default rather than inheriting one.
func PeekClientHelloSNI(r io.Reader) (sni string, buffered []byte, err error) {
	header := make([]byte, 5)
	if _, err := io.ReadFull(r, header); err != nil {
		return "", header, err
	}
	// TLS record: type(1)=0x16 handshake, version(2), length(2)
	if header[0] != 0x16 {
		return "", header, errNotClientHello
	}
	recordLen := int(header[3])<<8 | int(header[4])
	if recordLen <= 0 || recordLen > maxClientHelloRecord {
		return "", header, errNotClientHello
	}
	record := make([]byte, recordLen)
	if _, err := io.ReadFull(r, record); err != nil {
		return "", append(header, record...), err
	}
	buffered = append(header, record...)
	sni = parseClientHelloSNI(record)
	return sni, buffered, nil
}

// parseClientHelloSNI returns the server_name extension's host_name from the body of a handshake record (the
// ClientHello). Malformed input, or no SNI, gives an empty string.
func parseClientHelloSNI(record []byte) string {
	b := record
	// Handshake: msg_type(1)=0x01 ClientHello, length(3)
	if len(b) < 4 || b[0] != 0x01 {
		return ""
	}
	b = b[4:]
	// client_version(2) + random(32)
	if len(b) < 34 {
		return ""
	}
	b = b[34:]
	// session_id: len(1) + id
	if len(b) < 1 {
		return ""
	}
	sidLen := int(b[0])
	b = b[1:]
	if len(b) < sidLen {
		return ""
	}
	b = b[sidLen:]
	// cipher_suites: len(2) + suites
	if len(b) < 2 {
		return ""
	}
	csLen := int(b[0])<<8 | int(b[1])
	b = b[2:]
	if len(b) < csLen {
		return ""
	}
	b = b[csLen:]
	// compression_methods: len(1) + methods
	if len(b) < 1 {
		return ""
	}
	cmLen := int(b[0])
	b = b[1:]
	if len(b) < cmLen {
		return ""
	}
	b = b[cmLen:]
	// extensions: len(2) + extensions
	if len(b) < 2 {
		return ""
	}
	extTotal := int(b[0])<<8 | int(b[1])
	b = b[2:]
	if len(b) < extTotal {
		return ""
	}
	b = b[:extTotal]
	for len(b) >= 4 {
		extType := int(b[0])<<8 | int(b[1])
		extLen := int(b[2])<<8 | int(b[3])
		b = b[4:]
		if len(b) < extLen {
			return ""
		}
		extData := b[:extLen]
		b = b[extLen:]
		if extType != 0x0000 { // server_name
			continue
		}
		return parseServerNameExtension(extData)
	}
	return ""
}

// parseServerNameExtension returns the host_name (type 0) from a server_name extension's data.
func parseServerNameExtension(data []byte) string {
	// server_name_list: len(2)
	if len(data) < 2 {
		return ""
	}
	listLen := int(data[0])<<8 | int(data[1])
	data = data[2:]
	if len(data) < listLen {
		return ""
	}
	data = data[:listLen]
	for len(data) >= 3 {
		nameType := data[0]
		nameLen := int(data[1])<<8 | int(data[2])
		data = data[3:]
		if len(data) < nameLen {
			return ""
		}
		name := data[:nameLen]
		data = data[nameLen:]
		if nameType == 0x00 { // host_name
			return string(name)
		}
	}
	return ""
}
