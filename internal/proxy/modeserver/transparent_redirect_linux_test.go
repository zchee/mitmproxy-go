// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build integration && transparentprivileged && linux

package modeserver_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	json "encoding/json/v2"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/flowio"
)

const (
	redirectProxyUID  = 65534
	redirectClientUID = 65533
	redirectBody      = "transparent original destination reached\n"
	redirectOriginEnv = "MITMPROXY_TRANSPARENT_ORIGIN_CONFIG"
)

type redirectOriginConfig struct {
	Network     string
	Host        string
	TLS         bool
	Certificate string
	Key         string
	Counts      string
}

type redirectOriginCounts struct {
	Requests  int
	Responses int
	Errors    int
	Peer      string
	Path      string
}

type redirectFlowEvidence struct {
	Origin             connection.Address
	Listener           connection.Address
	Client             connection.Address
	ProxyUID           int
	ClientUID          int
	OriginCallbacks    redirectOriginCounts
	SavedRequests      int
	SavedResponses     int
	ProxyExemptPackets uint64
	RedirectedPackets  uint64
	Method             string
	Path               string
	Status             int
	ResponseBody       string
}

func TestTransparentRedirectAcceptance(t *testing.T) {
	if configuration := os.Getenv(redirectOriginEnv); configuration != "" {
		runRedirectOrigin(t, configuration)
		return
	}
	if os.Geteuid() != 0 {
		t.Fatal("transparent REDIRECT acceptance requires root; privilege failure is not a portability skip")
	}
	binary := os.Getenv("MITMPROXY_TEST_MITMDUMP")
	if !filepath.IsAbs(binary) {
		t.Fatal("MITMPROXY_TEST_MITMDUMP must name an absolute prebuilt executable")
	}
	if info, err := os.Stat(binary); err != nil || !info.Mode().IsRegular() || info.Mode()&0o111 == 0 {
		t.Fatalf("prebuilt mitmdump is unavailable: %v", err)
	}
	ip := requireRedirectTool(t, "ip", "/usr/sbin/ip", "/usr/bin/ip", "/sbin/ip")
	setpriv := requireRedirectTool(t, "setpriv", "/usr/bin/setpriv", "/bin/setpriv")
	curl := requireRedirectTool(t, "curl", "/usr/bin/curl", "/bin/curl")
	iptables := requireRedirectTool(t, "iptables", "/usr/sbin/iptables", "/sbin/iptables")
	ip6tables := requireRedirectTool(t, "ip6tables", "/usr/sbin/ip6tables", "/sbin/ip6tables")
	iptablesSave := requireRedirectTool(t, "iptables-save", "/usr/sbin/iptables-save", "/sbin/iptables-save")
	ip6tablesSave := requireRedirectTool(t, "ip6tables-save", "/usr/sbin/ip6tables-save", "/sbin/ip6tables-save")
	output := filepath.Join(filepath.Dir(binary), "transparent-redirect")
	if err := os.Mkdir(output, 0o755); err != nil {
		t.Fatalf("create fresh REDIRECT evidence directory: %v", err)
	}
	private, err := os.MkdirTemp("", "mitmproxy-transparent-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(private); err != nil {
			t.Error(err)
		}
	})
	if err := os.Chmod(private, 0o755); err != nil {
		t.Fatal(err)
	}
	certificate, key := redirectCertificate(t, private)
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, stopSignals := signal.NotifyContext(t.Context(), os.Interrupt, syscall.SIGTERM, syscall.SIGQUIT)
	defer stopSignals()
	runRedirectCommand(t, ctx, output, "namespaces-before", ip, "netns", "list")
	t.Cleanup(func() {
		if _, err := redirectCommand(context.WithoutCancel(ctx), output, "namespaces-after", ip, "netns", "list"); err != nil {
			t.Errorf("capture namespaces after teardown: %v", err)
		}
	})
	tests := map[string]struct {
		network string
		host    string
		tls     bool
	}{
		"IPv4_HTTP":  {network: "tcp4", host: "127.0.0.1"},
		"IPv4_HTTPS": {network: "tcp4", host: "127.0.0.1", tls: true},
		"IPv6_HTTP":  {network: "tcp6", host: "::1"},
		"IPv6_HTTPS": {network: "tcp6", host: "::1", tls: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			directory := filepath.Join(output, name)
			if err := os.Mkdir(directory, 0o755); err != nil {
				t.Fatal(err)
			}
			namespace := "mitm-transparent-" + strconv.Itoa(os.Getpid()) + "-" + strings.ToLower(rand.Text()[:8])
			namespacePath := filepath.Join("/run/netns", namespace)
			if _, err := os.Lstat(namespacePath); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("refuse to own an existing or inaccessible namespace %s: %v", namespace, err)
			}
			attempted := false
			t.Cleanup(func() {
				if !attempted {
					return
				}
				cleanup := context.WithoutCancel(ctx)
				if _, err := os.Lstat(namespacePath); errors.Is(err, os.ErrNotExist) {
					return
				}
				for label, tool := range map[string]string{"IPv4": iptablesSave, "IPv6": ip6tablesSave} {
					if _, err := redirectCommand(cleanup, directory, "teardown-"+label+"-counters", ip, "netns", "exec", namespace, tool, "-c", "-t", "nat"); err != nil {
						t.Errorf("capture owned namespace counters: %v", err)
					}
				}
				pids, err := redirectCommand(cleanup, directory, "teardown-processes", ip, "netns", "pids", namespace)
				if err != nil || len(strings.TrimSpace(string(pids))) != 0 {
					t.Errorf("owned namespace retained processes: %q, %v", pids, err)
				}
				if _, err := redirectCommand(cleanup, directory, "namespace-delete", ip, "netns", "delete", namespace); err != nil {
					t.Errorf("delete owned namespace: %v", err)
				}
				if _, err := os.Lstat(namespacePath); !errors.Is(err, os.ErrNotExist) {
					t.Errorf("namespace path survived teardown: %v", err)
				}
			})
			attempted = true
			runRedirectCommand(t, ctx, directory, "namespace-add", ip, "netns", "add", namespace)
			runRedirectCommand(t, ctx, directory, "loopback-up", ip, "-n", namespace, "link", "set", "lo", "up")
			runRedirectCommand(t, ctx, directory, "addresses", ip, "-n", namespace, "-j", "address", "show")
			for label, tool := range map[string]string{"IPv4": iptablesSave, "IPv6": ip6tablesSave} {
				runRedirectCommand(t, ctx, directory, "before-"+label+"-rules", ip, "netns", "exec", namespace, tool, "-c", "-t", "nat")
			}
			configuration := redirectOriginConfig{Network: tt.network, Host: tt.host, TLS: tt.tls, Certificate: certificate, Key: key, Counts: filepath.Join(directory, "origin-counts.json")}
			configurationPath := filepath.Join(private, name+"-origin.json")
			writeRedirectJSON(t, configurationPath, configuration)
			origin := startRedirectProcess(t, ctx, directory, "origin", regexp.MustCompile(`^TRANSPARENT_ORIGIN_READY (.+)$`), []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", redirectOriginEnv + "=" + configurationPath}, ip, "netns", "exec", namespace, self, "-test.run", "^TestTransparentRedirectAcceptance$", "-test.count=1", "-test.timeout=15m", "-test.v")
			originAddress := origin.awaitReady(t, ctx)
			originEndpoint, err := netip.ParseAddrPort(originAddress)
			if err != nil {
				t.Fatalf("origin readiness address: %v", err)
			}
			owned := filepath.Join(private, name+"-proxy")
			if err := os.Mkdir(owned, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Chown(owned, redirectProxyUID, redirectProxyUID); err != nil {
				t.Fatal(err)
			}
			confdir := filepath.Join(owned, "confdir")
			flows := filepath.Join(owned, "flows.mitm")
			proxy := startRedirectProcess(t, ctx, directory, "proxy", regexp.MustCompile(`Transparent Proxy listening at (.+)\.`), []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}, ip, "netns", "exec", namespace, setpriv, "--reuid", strconv.Itoa(redirectProxyUID), "--regid", strconv.Itoa(redirectProxyUID), "--clear-groups", "--no-new-privs", binary, "--mode", "transparent@"+net.JoinHostPort(tt.host, "0"), "--set", "confdir="+confdir, "--set", "ssl_verify_upstream_trusted_ca="+certificate, "--set", "save_stream_file="+flows)
			listenerAddress := proxy.awaitReady(t, ctx)
			listener, err := netip.ParseAddrPort(listenerAddress)
			if err != nil {
				t.Fatalf("proxy readiness address: %v", err)
			}
			ca, err := os.ReadFile(filepath.Join(confdir, "mitmproxy-ca-cert.pem"))
			if err != nil {
				t.Fatal(err)
			}
			publicCA := filepath.Join(directory, "proxy-ca-cert.pem")
			if err := os.WriteFile(publicCA, ca, 0o644); err != nil {
				t.Fatal(err)
			}
			clientCA := filepath.Join(private, name+"-proxy-ca-cert.pem")
			if err := os.WriteFile(clientCA, ca, 0o644); err != nil {
				t.Fatal(err)
			}
			nat, save := iptables, iptablesSave
			if tt.network == "tcp6" {
				nat, save = ip6tables, ip6tablesSave
			}
			runRedirectCommand(t, ctx, directory, "proxy-origin-exemption", ip, "netns", "exec", namespace, nat, "-w", "-t", "nat", "-A", "OUTPUT", "-m", "owner", "--uid-owner", strconv.Itoa(redirectProxyUID), "-j", "RETURN")
			runRedirectCommand(t, ctx, directory, "client-origin-redirect", ip, "netns", "exec", namespace, nat, "-w", "-t", "nat", "-A", "OUTPUT", "-p", "tcp", "-d", tt.host, "--dport", strconv.Itoa(int(originEndpoint.Port())), "-m", "owner", "--uid-owner", strconv.Itoa(redirectClientUID), "-j", "REDIRECT", "--to-ports", strconv.Itoa(int(listener.Port())))
			runRedirectCommand(t, ctx, directory, "installed-rules", ip, "netns", "exec", namespace, save, "-c", "-t", "nat")
			scheme := "http"
			if tt.tls {
				scheme = "https"
			}
			ancestorPaths := []string{directory}
			for parent := filepath.Dir(directory); ; parent = filepath.Dir(parent) {
				ancestorPaths = append(ancestorPaths, parent)
				if parent == "/" {
					break
				}
			}
			slices.Reverse(ancestorPaths)
			ancestorArgs := append([]string{"-ld"}, ancestorPaths...)
			clientArgs := []string{"netns", "exec", namespace, setpriv, "--reuid", strconv.Itoa(redirectClientUID), "--regid", strconv.Itoa(redirectClientUID), "--clear-groups", "--no-new-privs"}
			for label, arguments := range map[string][]string{
				"client-ca-stat":  {"/usr/bin/stat", "-c", "%A %U:%G %n", publicCA, clientCA},
				"client-ancestry": append([]string{"/bin/ls"}, ancestorArgs...),
				"client-id":       {"/usr/bin/id"},
				"client-apparmor": {"/bin/cat", "/proc/self/attr/apparmor/current"},
			} {
				if _, err := redirectCommand(ctx, directory, label, ip, slices.Concat(clientArgs, arguments)...); err != nil {
					t.Logf("diagnostic %s: %v", label, err)
				}
			}
			if _, err := redirectCommand(ctx, directory, "proxy-ca-stat", ip, "netns", "exec", namespace, setpriv, "--reuid", strconv.Itoa(redirectProxyUID), "--regid", strconv.Itoa(redirectProxyUID), "--clear-groups", "--no-new-privs", "/usr/bin/stat", "-c", "%A %U:%G %n", publicCA); err != nil {
				t.Logf("diagnostic proxy-ca-stat: %v", err)
			}
			for label, arguments := range map[string][]string{
				"root-umask":             {"/bin/sh", "-c", "umask"},
				"root-ancestry":          append([]string{"/bin/ls"}, ancestorArgs...),
				"root-protected-regular": {"/bin/cat", "/proc/sys/fs/protected_regular"},
				"root-curl-apparmor":     {"/bin/grep", "-i", "curl", "/sys/kernel/security/apparmor/profiles"},
			} {
				if _, err := redirectCommand(ctx, directory, label, arguments[0], arguments[1:]...); err != nil {
					t.Logf("diagnostic %s: %v", label, err)
				}
			}
			curlOutput, curlErr := redirectCommand(ctx, directory, "curl", ip, "netns", "exec", namespace, setpriv, "--reuid", strconv.Itoa(redirectClientUID), "--regid", strconv.Itoa(redirectClientUID), "--clear-groups", "--no-new-privs", curl, "--disable", "--noproxy", "*", "--fail", "--silent", "--show-error", "--http1.1", "--max-time", "30", "--cacert", clientCA, "--write-out", "\nCURL_METRICS %{local_ip} %{local_port} %{remote_ip} %{remote_port} %{http_code}\n", scheme+"://"+originAddress+"/redirected")
			if _, err := redirectCommand(context.WithoutCancel(ctx), directory, "root-audit", "/bin/sh", "-c", "dmesg | grep -iE 'apparmor|audit' | tail -n 50"); err != nil {
				t.Logf("diagnostic root-audit: %v", err)
			}
			if curlErr != nil {
				t.Fatalf("curl: %v", curlErr)
			}
			body, metrics, ok := strings.Cut(string(curlOutput), "\nCURL_METRICS ")
			if !ok || body != redirectBody {
				t.Fatalf("curl body/metrics = %q", curlOutput)
			}
			fields := strings.Fields(metrics)
			if len(fields) != 5 || fields[4] != "200" || fields[2] != originEndpoint.Addr().String() || fields[3] != strconv.Itoa(int(originEndpoint.Port())) {
				t.Fatalf("curl connection metrics = %q", metrics)
			}
			clientPort, err := strconv.Atoi(fields[1])
			if err != nil {
				t.Fatal(err)
			}
			counters := runRedirectCommand(t, ctx, directory, "completed-counters", ip, "netns", "exec", namespace, save, "-c", "-t", "nat")
			exempt, redirected := redirectRuleCounts(t, counters)
			proxy.stop(t)
			origin.stop(t)
			var observed redirectOriginCounts
			counts, err := os.ReadFile(configuration.Counts)
			if err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(counts, &observed); err != nil {
				t.Fatal(err)
			}
			if observed.Requests != 1 || observed.Responses != 1 || observed.Errors != 0 || observed.Path != "/redirected" {
				t.Fatalf("real-origin callbacks = %+v", observed)
			}
			flowBytes, err := os.ReadFile(flows)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(directory, "flows.mitm"), flowBytes, 0o644); err != nil {
				t.Fatal(err)
			}
			originTuple := connection.Address{Host: originEndpoint.Addr().String(), Port: int(originEndpoint.Port())}
			listenerTuple := connection.Address{Host: listener.Addr().String(), Port: int(listener.Port())}
			clientTuple := connection.Address{Host: fields[0], Port: clientPort}
			observation := inspectRedirectFlow(t, flowBytes, originTuple, listenerTuple, clientTuple)
			observation.OriginCallbacks, observation.ProxyExemptPackets, observation.RedirectedPackets = observed, exempt, redirected
			writeRedirectJSON(t, filepath.Join(directory, "observed-flow-evidence.json"), observation)
		})
	}
}

func redirectRuleCounts(t *testing.T, counters []byte) (uint64, uint64) {
	t.Helper()
	var exempt, redirected uint64
	for line := range strings.SplitSeq(string(counters), "\n") {
		prefix, _, ok := strings.Cut(line, "] ")
		if !ok || !strings.HasPrefix(prefix, "[") {
			continue
		}
		packets, _, _ := strings.Cut(strings.TrimPrefix(prefix, "["), ":")
		count, err := strconv.ParseUint(packets, 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(line, "--uid-owner "+strconv.Itoa(redirectProxyUID)) && strings.Contains(line, "-j RETURN") {
			exempt += count
		}
		if strings.Contains(line, "--uid-owner "+strconv.Itoa(redirectClientUID)) && strings.Contains(line, "-j REDIRECT") {
			redirected += count
		}
	}
	if exempt == 0 || redirected == 0 {
		t.Fatalf("missing real proxy-origin exemption or client REDIRECT packets: exempt=%d redirected=%d\n%s", exempt, redirected, counters)
	}
	return exempt, redirected
}

func inspectRedirectFlow(t *testing.T, data []byte, origin, listener, client connection.Address) redirectFlowEvidence {
	t.Helper()
	reader := flowio.NewReader(bytes.NewReader(data))
	item, err := reader.Next()
	if err != nil {
		t.Fatalf("read emitted flow: %v", err)
	}
	httpFlow, ok := item.(*flow.HTTPFlow)
	if !ok || httpFlow.Request == nil || httpFlow.Response == nil || httpFlow.Error != nil || httpFlow.ServerConn == nil || httpFlow.ClientConn == nil {
		t.Fatalf("incomplete emitted HTTP flow: %T %+v", item, item)
	}
	for name, pair := range map[string]struct{ want, got *connection.Address }{
		"pre-NAT origin":  {want: &origin, got: httpFlow.ServerConn.Address},
		"actual listener": {want: &listener, got: httpFlow.ClientConn.Sockname},
		"actual client":   {want: &client, got: httpFlow.ClientConn.Peername},
	} {
		if diff := gocmp.Diff(pair.want, pair.got); diff != "" {
			t.Fatalf("%s (-want +got):\n%s", name, diff)
		}
	}
	if origin.Port == listener.Port || httpFlow.Request.Path != "/redirected" || httpFlow.Request.Method != "GET" || httpFlow.Response.StatusCode != http.StatusOK {
		t.Fatal("flow failed original-destination or HTTP state assertions")
	}
	body, err := httpFlow.Response.Content()
	if err != nil || string(body) != redirectBody {
		t.Fatalf("saved response = %q, %v", body, err)
	}
	if _, err := reader.Next(); !errors.Is(err, io.EOF) {
		t.Fatalf("expected exactly one saved request/response flow, next error=%v", err)
	}
	return redirectFlowEvidence{Origin: origin, Listener: listener, Client: client, ProxyUID: redirectProxyUID, ClientUID: redirectClientUID, SavedRequests: 1, SavedResponses: 1, Method: httpFlow.Request.Method, Path: httpFlow.Request.Path, Status: httpFlow.Response.StatusCode, ResponseBody: string(body)}
}

func runRedirectOrigin(t *testing.T, path string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var configuration redirectOriginConfig
	if err := json.Unmarshal(data, &configuration); err != nil {
		t.Fatal(err)
	}
	ctx, stop := signal.NotifyContext(t.Context(), os.Interrupt, syscall.SIGTERM, syscall.SIGQUIT)
	defer stop()
	listener, err := net.Listen(configuration.Network, net.JoinHostPort(configuration.Host, "0"))
	if err != nil {
		t.Fatal(err)
	}
	if configuration.TLS {
		certificate, err := tls.LoadX509KeyPair(configuration.Certificate, configuration.Key)
		if err != nil {
			_ = listener.Close()
			t.Fatal(err)
		}
		listener = tls.NewListener(listener, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12})
	}
	var mu sync.Mutex
	var counts redirectOriginCounts
	server := &http.Server{ReadHeaderTimeout: 30 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		counts.Requests++
		counts.Peer, counts.Path = r.RemoteAddr, r.URL.Path
		mu.Unlock()
		w.Header().Set("Connection", "close")
		n, err := io.WriteString(w, redirectBody)
		mu.Lock()
		defer mu.Unlock()
		if err != nil || n != len(redirectBody) {
			counts.Errors++
		} else {
			counts.Responses++
		}
	})}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	if _, err := fmt.Fprintln(os.Stdout, "TRANSPARENT_ORIGIN_READY "+listener.Addr().String()); err != nil {
		_ = server.Close()
		<-done
		t.Fatal(err)
	}
	select {
	case <-ctx.Done():
	case err := <-done:
		t.Fatalf("origin exited before shutdown: %v", err)
	}
	shutdown, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 30*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdown); err != nil {
		_ = server.Close()
		t.Error(err)
	}
	if err := <-done; !errors.Is(err, http.ErrServerClosed) {
		t.Errorf("origin serve: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	writeRedirectJSON(t, configuration.Counts, counts)
}

func redirectCertificate(t *testing.T, directory string) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	certificate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Transparent acceptance origin"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true, IsCA: true, IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certificatePath, keyPath := filepath.Join(directory, "origin-cert.pem"), filepath.Join(directory, "origin-key.pem")
	if err := os.WriteFile(certificatePath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certificatePath, keyPath
}

func writeRedirectJSON(t *testing.T, path string, value any) {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}
