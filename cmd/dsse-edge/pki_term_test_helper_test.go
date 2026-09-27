package main

import "strings"

type pkiTermBody struct {
	*strings.Reader
	before func()
}

func (b *pkiTermBody) Read(p []byte) (int, error) {
	if b.before != nil {
		f := b.before
		b.before = nil
		f()
	}
	return b.Reader.Read(p)
}
func (b *pkiTermBody) Close() error { return nil }
