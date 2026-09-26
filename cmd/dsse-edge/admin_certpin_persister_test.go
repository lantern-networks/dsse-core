package main

import (
	"bytes"
	"errors"
)

type candidateNthPersister struct {
	data          []byte
	calls, failAt int
}

func (p *candidateNthPersister) Load() ([]byte, error) { return bytes.Clone(p.data), nil }
func (p *candidateNthPersister) Save(b []byte) error {
	p.calls++
	if p.calls == p.failAt {
		return errors.New("/private/candidate-state: write refused")
	}
	p.data = bytes.Clone(b)
	return nil
}
