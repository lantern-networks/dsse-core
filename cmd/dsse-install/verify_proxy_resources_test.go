package main

import (
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestProxyResourceReportUsesTheActualHAProxyAndKernelValues(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix socket verification runs on the Linux Docker host")
	}
	for _, limits := range []struct {
		soft, hard string
		ok         bool
	}{{"524288", "524288", true}, {"1024", "524288", false}} {
		t.Run(limits.soft, func(t *testing.T) {
			dir, err := os.MkdirTemp("/tmp", "dsse-proxy-")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { os.RemoveAll(dir) })
			socket := filepath.Join(dir, "stats.sock")
			l, e := net.Listen("unix", socket)
			if e != nil {
				t.Fatal(e)
			}
			defer l.Close()
			go func() {
				c, e := l.Accept()
				if e != nil {
					return
				}
				defer c.Close()
				b := make([]byte, 64)
				c.Read(b)
				io.WriteString(c, "Version: 2.9.15\nMaxconn: 262121\nUlimit-n: 524288\n")
			}()
			r, e := readProxyResourceInfo(socket, "Max open files            "+limits.soft+" "+limits.hard+" files\n")
			if (e == nil) != limits.ok {
				t.Fatal("descriptor resources misclassified", e)
			}
			if r.MaxConnections != 262121 || r.HardNofile != limits.hard {
				t.Fatal("effective values were replaced with constants")
			}
		})
	}
}
