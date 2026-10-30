//go:build !windows

package main

func captureStepUpOwner(pid uint32) stepUpOwner { return stepUpOwner{} }
