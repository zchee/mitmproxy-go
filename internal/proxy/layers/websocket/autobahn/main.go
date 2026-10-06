// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:]); err != nil {
		slog.Error("Autobahn gate failed", "error", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("expected origin, address, port, wait, configure, seconds, guard or verify")
	}
	switch {
	case args[0] == "origin" && len(args) == 3:
		address, stop, err := startOrigin(args[1])
		if err != nil {
			return err
		}
		defer func() {
			if err := stop(); err != nil {
				slog.Error("echo origin shutdown", "error", err)
			}
		}()
		if err := writeJSON(args[2], struct {
			Address string `json:"address"`
		}{address}); err != nil {
			return err
		}
		<-ctx.Done()
		return nil
	case args[0] == "address" && len(args) == 2:
		ready, err := loadJSON[struct {
			Address string `json:"address"`
		}](args[1])
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(os.Stdout, ready.Address)
		return err
	case args[0] == "port" && len(args) == 3:
		address, err := configuredAddress(args[1], args[2])
		if err != nil {
			return err
		}
		listener, err := preferredListener(address)
		if err != nil {
			return err
		}
		_, port, err := net.SplitHostPort(listener.Addr().String())
		closeErr := listener.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
		_, err = fmt.Fprintln(os.Stdout, port)
		return err
	case args[0] == "wait" && len(args) == 2:
		ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		return waitReady(ctx, args[1])
	case args[0] == "configure" && len(args) >= 5:
		image, err := configureSuite(args[1], args[2], args[3], args[4], args[5:]...)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(os.Stdout, image)
		return err
	case args[0] == "seconds" && len(args) == 2:
		limit, err := timeoutSeconds(args[1])
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(os.Stdout, limit)
		return err
	case args[0] == "guard" && len(args) == 3:
		limit, err := timeoutSeconds(args[1])
		if err != nil {
			return err
		}
		pid, err := strconv.Atoi(args[2])
		if err != nil || pid < 2 {
			return fmt.Errorf("guard requires a positive child process ID")
		}
		if ctx.Err() != nil {
			return nil
		}
		timer := time.NewTimer(time.Duration(limit) * time.Second)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return nil
		case <-timer.C:
			process, err := os.FindProcess(pid)
			if err != nil {
				return err
			}
			if err := process.Signal(syscall.SIGTERM); err != nil {
				return err
			}
			return fmt.Errorf("autobahn suite exceeded its hang guard")
		}
	case args[0] == "verify" && len(args) >= 4:
		result, err := verifyFiles(args[1], args[2], args[4:]...)
		if err != nil {
			return err
		}
		return writeJSON(args[3], result)
	default:
		return fmt.Errorf("invalid command or argument count")
	}
}

func timeoutSeconds(value string) (int, error) {
	limit, err := strconv.Atoi(value)
	if err != nil || limit < 1 || limit > 86400 {
		return 0, fmt.Errorf("WS_GATE_TIMEOUT_SECONDS must be between 1 and 86400")
	}
	return limit, nil
}

func configuredAddress(host, port string) (string, error) {
	n, err := strconv.Atoi(port)
	if host == "" || err != nil || n < 0 || n > 65535 {
		return "", fmt.Errorf("listen host must be nonempty and port must be between 0 and 65535")
	}
	return net.JoinHostPort(host, port), nil
}

func configureSuite(manifestPath, configPath, target, output string, prefixes ...string) (string, error) {
	m, err := loadJSON[manifest](manifestPath)
	if err != nil {
		return "", err
	}
	if err := validateManifest(m); err != nil {
		return "", err
	}
	config, err := loadJSON[suiteConfig](configPath)
	if err != nil {
		return "", err
	}
	if config.Image != m.Image {
		return "", fmt.Errorf("config and manifest image digests differ")
	}
	u, err := url.Parse(target)
	if err != nil || u.Scheme != "ws" || u.Host == "" || u.User != nil {
		return "", fmt.Errorf("target must be a credential-free ws URL")
	}
	config.Outdir = "/reports/clients"
	config.Servers = []suiteServer{{Agent: suiteAgent, URL: target}}
	config.Cases = make([]string, 0, len(m.Cases))
	if slices.Contains(prefixes, "") {
		return "", fmt.Errorf("case prefixes must be nonempty")
	}
	for _, c := range m.Cases {
		selected := len(prefixes) == 0
		for _, prefix := range prefixes {
			if c.ID == prefix || strings.HasPrefix(c.ID, prefix+".") {
				if selected {
					return "", fmt.Errorf("overlapping case prefixes for %s", c.ID)
				}
				selected = true
			}
		}
		if selected {
			config.Cases = append(config.Cases, c.ID)
		}
	}
	if len(config.Cases) == 0 {
		return "", fmt.Errorf("case prefixes select no frozen cases")
	}
	config.ExcludeCases, config.ExcludeAgentCases = []string{}, map[string][]string{}
	return m.Image, writeJSON(output, config)
}

func waitReady(ctx context.Context, target string) error {
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	var lastErr error
	for {
		address := target
		if filepath.Ext(target) == ".json" {
			ready, err := loadJSON[struct {
				Address string `json:"address"`
			}](target)
			if err != nil {
				lastErr = err
				address = ""
			} else {
				address = ready.Address
			}
		}
		if address != "" {
			conn, err := (&net.Dialer{Timeout: 250 * time.Millisecond}).DialContext(ctx, "tcp", address)
			if err == nil {
				return conn.Close()
			}
			lastErr = err
		}
		select {
		case <-ctx.Done():
			buf := make([]byte, 1<<20)
			n := runtime.Stack(buf, true)
			return fmt.Errorf("readiness: %w; last error: %v\n%s", ctx.Err(), lastErr, buf[:n])
		case <-ticker.C:
		}
	}
}
