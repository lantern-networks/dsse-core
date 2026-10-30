package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

type proxyResourceInfo struct {
	Service        string `json:"service"`
	MemoryMB       uint64 `json:"memory_mb"`
	Version        string `json:"version"`
	MaxConnections uint64 `json:"max_connections"`
	SoftNofile     string `json:"soft_nofile"`
	HardNofile     string `json:"hard_nofile"`
	HAProxyNofile  uint64 `json:"haproxy_nofile"`
}

func readProxyResourceInfo(socket, limits string) (proxyResourceInfo, error) {
	var out proxyResourceInfo
	c, err := net.DialTimeout("unix", socket, 3*time.Second)
	if err != nil {
		return out, err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err = io.WriteString(c, "show info\n"); err != nil {
		return out, err
	}
	raw, err := io.ReadAll(io.LimitReader(c, 64<<10))
	if err != nil {
		return out, err
	}
	for _, line := range strings.Split(string(raw), "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		switch key {
		case "Version":
			out.Version = value
		case "Memmax_MB":
			out.MemoryMB, _ = strconv.ParseUint(value, 10, 64)
		case "Maxconn":
			out.MaxConnections, _ = strconv.ParseUint(value, 10, 64)
		case "Ulimit-n":
			out.HAProxyNofile, _ = strconv.ParseUint(value, 10, 64)
		}
	}
	for _, line := range strings.Split(limits, "\n") {
		if strings.HasPrefix(line, "Max open files") {
			f := strings.Fields(line)
			if len(f) >= 5 {
				out.SoftNofile, out.HardNofile = f[3], f[4]
			}
		}
	}
	if out.MaxConnections == 0 || out.Version == "" || out.SoftNofile == "" || out.HardNofile == "" {
		return out, fmt.Errorf("proxy capacity could not be established")
	}
	if out.SoftNofile != out.HardNofile {
		return out, fmt.Errorf("proxy soft descriptor limit was not raised: soft=%s hard=%s actual Maxconn=%d", out.SoftNofile, out.HardNofile, out.MaxConnections)
	}
	return out, nil
}

// This explicitly local, read-only verification requires the Linux Docker host
// and permission to read the private stats socket through /proc/PID/root. It
// never opens a TCP management listener or treats an unavailable probe as PASS.
func verifyLocalProxyResources(dir string) ([]proxyResourceInfo, error) {
	if runtime.GOOS != "linux" {
		return nil, fmt.Errorf("run proxy resource verification on the Linux Docker host")
	}
	dir, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	if _, err = os.Stat(filepath.Join(dir, "docker-compose.yml")); err != nil {
		return nil, err
	}
	run := func(args ...string) ([]byte, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		c := exec.CommandContext(ctx, "docker", args...)
		c.Dir = dir
		return c.Output()
	}
	// Deployments may start Compose with an explicit -p instead of the directory
	// name. Discover by its exact ownership label, not a guessed project name.
	ids, err := run("ps", "--filter", "label=com.docker.compose.project.working_dir="+dir, "--format", "{{.ID}}")
	if err != nil {
		return nil, fmt.Errorf("read owned Compose runtime: %w", err)
	}
	var result []proxyResourceInfo
	for _, id := range strings.Fields(string(ids)) {
		raw, e := run("inspect", id)
		if e != nil {
			return nil, e
		}
		var rows []struct {
			State  struct{ Pid int }
			Config struct{ Labels map[string]string }
			Mounts []struct{ Source, Destination string }
		}
		if json.Unmarshal(raw, &rows) != nil || len(rows) != 1 {
			return nil, fmt.Errorf("invalid container inspection")
		}
		row := rows[0]
		if filepath.Clean(row.Config.Labels["com.docker.compose.project.working_dir"]) != dir {
			return nil, fmt.Errorf("container is outside this deployment")
		}
		config := ""
		for _, m := range row.Mounts {
			if m.Destination == "/usr/local/etc/haproxy/haproxy.cfg" {
				config = filepath.Base(m.Source)
			}
		}
		if config == "" {
			continue
		}
		if row.State.Pid <= 0 {
			return nil, fmt.Errorf("proxy is not running")
		}
		proc := filepath.Join("/proc", strconv.Itoa(row.State.Pid))
		limits, e := os.ReadFile(filepath.Join(proc, "limits"))
		if e != nil {
			return nil, e
		}
		info, e := readProxyResourceInfo(filepath.Join(proc, "root/tmp", "dsse-"+config+".sock"), string(limits))
		if e != nil {
			return nil, fmt.Errorf("proxy %s: %w", row.Config.Labels["com.docker.compose.service"], e)
		}
		info.Service = row.Config.Labels["com.docker.compose.service"]
		result = append(result, info)
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("no running proxy in this deployment could be measured")
	}
	return result, nil
}
