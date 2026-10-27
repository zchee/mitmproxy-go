module github.com/zchee/mitmproxy-go

replace go.yaml.in/yaml/v4 => github.com/zchee/yaml-go-yaml/v4 v4.0.0-rc.6.0.20261016233001-98da9bfb2950

go 1.27.3

require (
	charm.land/bubbles/v2 v2.2.1
	charm.land/bubbletea/v2 v2.1.0
	charm.land/lipgloss/v2 v2.0.6
	codeberg.org/miekg/dns v0.6.119
	github.com/alecthomas/chroma/v2 v2.27.0
	github.com/andybalholm/brotli v1.2.6
	github.com/bufbuild/protocompile v0.14.1
	github.com/charmbracelet/colorprofile v0.4.3
	github.com/charmbracelet/x/ansi v0.11.9
	github.com/charmbracelet/x/exp/teatest/v2 v2.0.0-20261018003744-cb897cb4ed72
	github.com/charmbracelet/x/term v0.2.2
	github.com/chromedp/cdproto v0.158.4
	github.com/chromedp/chromedp v0.21.0
	github.com/dlclark/regexp2 v1.12.0
	github.com/ebitengine/purego v0.11.2
	github.com/go-ldap/ldap/v3 v3.4.15
	github.com/google/btree v1.1.3
	github.com/google/go-cmp v0.7.0
	github.com/itchyny/timefmt-go v0.1.9
	github.com/klauspost/compress v1.20.3
	github.com/pion/dtls/v3 v3.1.15
	github.com/quic-go/qpack v0.6.0
	github.com/quic-go/quic-go v0.64.1
	github.com/rivo/uniseg v0.4.7
	github.com/shamaton/msgpack/v3 v3.2.5
	github.com/shirou/gopsutil/v4 v4.26.9
	github.com/spf13/cobra v1.10.2
	github.com/spf13/pflag v1.0.10
	github.com/zchee/gows v0.1.1
	go.opentelemetry.io/otel v1.47.0
	go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp v1.47.0
	go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp v1.47.0
	go.opentelemetry.io/otel/metric v1.47.0
	go.opentelemetry.io/otel/sdk v1.47.0
	go.opentelemetry.io/otel/sdk/metric v1.47.0
	go.opentelemetry.io/otel/trace v1.47.0
	go.opentelemetry.io/proto/otlp v1.11.0
	go.starlark.net v0.0.0-20261021141710-4f4267fb140d
	go.uber.org/goleak v1.3.0
	go.yaml.in/yaml/v4 v4.0.0-rc.6
	golang.design/x/clipboard v0.11.0
	golang.org/x/crypto v0.58.0
	golang.org/x/image v0.47.0
	golang.org/x/net v0.61.0
	golang.org/x/sys v0.49.0
	golang.org/x/text v0.43.0
	golang.zx2c4.com/wireguard v0.0.0-20261006164505-2631ce99a06f
	google.golang.org/protobuf v1.36.12
	gvisor.dev/gvisor v0.0.0-20261019180230-45aa8aedf6f1
	software.sslmate.com/src/go-pkcs12 v0.7.4
)

require (
	github.com/Azure/go-ntlmssp v0.1.1 // indirect
	github.com/atotto/clipboard v0.1.4 // indirect
	github.com/aymanbagabas/go-udiff v0.4.1 // indirect
	github.com/cenkalti/backoff/v5 v5.0.3 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/charmbracelet/ultraviolet v0.0.0-20261008173134-6b8d4baf91b4 // indirect
	github.com/charmbracelet/x/exp/golden v0.0.0-20251109135125-8916d276318f // indirect
	github.com/charmbracelet/x/termios v0.1.1 // indirect
	github.com/charmbracelet/x/windows v0.2.2 // indirect
	github.com/clipperhouse/displaywidth v0.11.0 // indirect
	github.com/clipperhouse/uax29/v2 v2.7.0 // indirect
	github.com/dlclark/regexp2/v2 v2.2.1 // indirect
	github.com/go-asn1-ber/asn1-ber v1.5.8 // indirect
	github.com/go-json-experiment/json v0.0.0-20260213210345-44df1a37e875 // indirect
	github.com/go-logr/logr v1.4.4 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/go-ole/go-ole v1.2.6 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.30.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/lucasb-eyer/go-colorful v1.4.1 // indirect
	github.com/lufia/plan9stats v0.0.0-20211012122336-39d0f177ccd0 // indirect
	github.com/mattn/go-runewidth v0.0.30 // indirect
	github.com/muesli/cancelreader v0.2.2 // indirect
	github.com/pion/logging v0.2.4 // indirect
	github.com/pion/transport/v5 v5.1.1 // indirect
	github.com/power-devops/perfstat v0.0.0-20260805114148-88456608a4f6 // indirect
	github.com/tklauser/go-sysconf v0.4.0 // indirect
	github.com/tklauser/numcpus v0.12.0 // indirect
	github.com/xo/terminfo v1.0.0 // indirect
	github.com/yusufpapurcu/wmi v1.2.4 // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlptrace v1.47.0 // indirect
	go.opentelemetry.io/otel/log v1.47.0 // indirect
	golang.design/x/x11 v0.2.0 // indirect
	golang.org/x/exp v0.0.0-20261014143641-f0251eb4aa3e // indirect
	golang.org/x/exp/shiny v0.0.0-20261014143641-f0251eb4aa3e // indirect
	golang.org/x/mobile v0.0.0-20261011034528-197770444867 // indirect
	golang.org/x/sync v0.24.0 // indirect
	golang.org/x/time v0.16.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20260928230214-8a89bd6388cc // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260928230214-8a89bd6388cc // indirect
	google.golang.org/grpc v1.83.2 // indirect
)
