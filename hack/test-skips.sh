#!/usr/bin/env bash
# Keep pipefail at the caller: this reader cannot observe the producer's status.
set -euo pipefail

case "${TEST_SKIPS_ENFORCE:-0}" in
'' | 0 | false | off) enforce=0 ;;
1 | true | on) enforce=1 ;;
*)
  printf 'test-skips: invalid TEST_SKIPS_ENFORCE value\n' >&2; exit 2
  ;;
esac

# POSIX awk is available on all runners, including macOS's Bash 3.2.
# The byte locale makes JSON Unicode escapes independent of the host locale.
# shellcheck disable=SC2016 # The program uses awk fields, not shell expansions.
TEST_SKIPS_ENFORCE="${enforce}" LC_ALL=C "${TEST_SKIPS_AWK:-awk}" '
function whitespace() {
  while (substr(line, position, 1) ~ /[ \t\r\n]/ && position <= length(line)) position++
}
function hex4(    text, value, digit, n) {
  text = substr(line, position, 4)
  if (length(text) != 4 || text ~ /[^0-9a-fA-F]/) { invalid = 1; return 0 }
  position += 4
  value = 0
  for (n = 1; n <= 4; n++) {
    digit = index("0123456789abcdef", tolower(substr(text, n, 1))) - 1
    value = value * 16 + digit
  }
  return value
}
function utf8(value) {
  if (value < 128) return sprintf("%c", value)
  if (value < 2048) return sprintf("%c%c", 192 + int(value / 64), 128 + value % 64)
  if (value < 65536) return sprintf("%c%c%c", 224 + int(value / 4096), 128 + int(value / 64) % 64, 128 + value % 64)
  return sprintf("%c%c%c%c", 240 + int(value / 262144), 128 + int(value / 4096) % 64, 128 + int(value / 64) % 64, 128 + value % 64)
}
function string(    result, char, code, low) {
  if (substr(line, position++, 1) != "\"") { invalid = 1; return "" }
  result = ""
  while (position <= length(line)) {
    char = substr(line, position++, 1)
    if (char == "\"") return result
    if (char ~ /[\001-\037]/) { invalid = 1; return "" }
    if (char != "\\") { result = result char; continue }
    char = substr(line, position++, 1)
    if (char == "\"" || char == "\\" || char == "/") result = result char
    else if (char == "b") result = result sprintf("%c", 8)
    else if (char == "f") result = result sprintf("%c", 12)
    else if (char == "n") result = result "\n"
    else if (char == "r") result = result "\r"
    else if (char == "t") result = result "\t"
    else if (char == "u") {
      code = hex4()
      if (code >= 55296 && code <= 56319) {
        if (substr(line, position, 2) != "\\u") { invalid = 1; return "" }
        position += 2
        low = hex4()
        if (low < 56320 || low > 57343) { invalid = 1; return "" }
        code = 65536 + (code - 55296) * 1024 + low - 56320
      } else if (code >= 56320 && code <= 57343) { invalid = 1; return "" }
      result = result utf8(code)
    } else { invalid = 1; return "" }
    if (invalid) return ""
  }
  invalid = 1
  return ""
}
function parse(    key, value, start, field) {
  for (field in event) delete event[field]
  position = 1
  invalid = 0
  whitespace()
  if (substr(line, position++, 1) != "{") return 0
  whitespace()
  while (substr(line, position, 1) != "}") {
    key = string()
    whitespace()
    if (invalid || substr(line, position++, 1) != ":") return 0
    whitespace()
    if (substr(line, position, 1) == "\"") value = string()
    else {
      start = position
      while (position <= length(line) && substr(line, position, 1) !~ /[,} \t\r\n]/) position++
      value = substr(line, start, position - start)
      if (value !~ /^-?[0-9]+([.][0-9]+)?([eE][+-]?[0-9]+)?$/ && value != "null" && value != "true" && value != "false") return 0
    }
    if (invalid || key in event) return 0
    event[key] = value
    whitespace()
    if (substr(line, position, 1) == "}") break
    if (substr(line, position++, 1) != ",") return 0
    whitespace()
    if (substr(line, position, 1) == "}") return 0
  }
  position++
  whitespace()
  return position > length(line) && event["Action"] != ""
}
function classify(package, test, message) {
  if (index(message, "differential test: build with -tags difftest to run it")) return "environment"
  if (package == "github.com/zchee/mitmproxy-go/options") {
    if (test == "TestPyJoinWindows" && index(message, "drive letters and UNC volumes exist only on Windows")) return "GOOS"
    if (test == "TestPyAbsoluteWindows" && index(message, "drive letters exist only on Windows")) return "GOOS"
  }
  if (package == "github.com/zchee/mitmproxy-go/internal/local") {
    if (test == "TestLinuxNative" && index(message, "synthetic peer uses Unix datagrams and a Unix shell")) return "GOOS"
    if (test ~ /^TestMacOS(Lifecycle|LaunchErrors|Lifetime|Streams|StreamLifetime|UDPDestination|BadFlow)$/ && index(message, "synthetic starter uses a Unix shell and Unix sockets")) return "GOOS"
    if (test == "TestAcquireArtifactSymlinkOverride" && index(message, "creating symlink fixtures requires Windows developer mode or administrator privileges")) return "GOOS"
    if (test == "TestAcquirePinnedArtifacts" && index(message, "MITMPROXY_TEST_REDIRECTOR_DOWNLOAD=1")) return "environment"
    if (test == "TestWindowsPipeFixture" && index(message, "subprocess fixture is launched by the Windows contract cases")) return "environment"
  }
  if (index(message, "cannot create a foreign-owned file:") || index(message, "cannot create symlink:") || index(message, "POSIX write permissions require a non-root user")) return "privilege"
  if (package == "github.com/zchee/mitmproxy-go/internal/proxy/modeserver" && index(message, "IPv6")) {
    # Explicitly name the capability-sensitive transport rows; an unfamiliar
    # skip must not become acceptable merely because its message says IPv6.
    if (test == "TestBothListenerDualStack" || test ~ /^TestStandaloneDNSWireTransports\/IPv6_/ || test == "TestBoundPacketFactoryRollback" || test ~ /^TestDualStack(PortCollision)?$/) return "capability"
  }
  if (package == "github.com/zchee/mitmproxy-go/internal/tools/cmdline" && test ~ /^TestCompletionScripts\/success:_(bash|zsh|fish|powershell)\/syntax$/ && index(message, "shell syntax check requires ")) return "capability"
  if (index(message, "GOOS") || tolower(message) ~ /(^|[^[:alnum:]_])(windows|linux|macos|darwin|freebsd|openbsd|netbsd|dragonfly|solaris|illumos|plan ?9|android|ios|aix)([^[:alnum:]_]|$)/) return "GOOS"
  return "unknown"
}
function summary_line(text) {
  print text
  if (summary != "") print text >> summary
}
BEGIN {
  enforce = ENVIRON["TEST_SKIPS_ENFORCE"] + 0
  summary = ENVIRON["GITHUB_STEP_SUMMARY"]
  classes[1] = "GOOS"
  classes[2] = "environment"
  classes[3] = "privilege"
  classes[4] = "capability"
  classes[5] = "unknown"
}
{
  line = $0
  if (!parse()) {
    printf "test-skips: invalid JSON event at input line %d\n", NR > "/dev/stderr"
    errors++
    next
  }
  action = event["Action"]
  package = event["Package"]
  test = event["Test"]
  key = package SUBSEP test
  if (action == "output" || action == "build-output") {
    printf "%s", event["Output"]
    if (test != "") output[key] = output[key] event["Output"]
    else if (index(event["Output"], "[no test files]")) no_tests[package] = 1
  } else if (action == "skip") {
    if (test == "") {
      if (no_tests[package]) no_test_files++
      else package_skips++
      printf "test-skips: package %s (%s)\n", package, no_tests[package] ? "no test files" : "no per-test skip"
      delete no_tests[package]
    } else {
      message = output[key]
      reason = ""
      reason_count = split(message, reason_lines, "\n")
      for (reason_index = 1; reason_index <= reason_count; reason_index++) {
        reason_line = reason_lines[reason_index]
        if (reason_line ~ /^[[:space:]]*(=== [A-Z]+ |--- (SKIP|PASS|FAIL):)/) continue
        if (reason_line ~ /^[[:space:]]*[^[:space:]]+[.]go:[0-9]+:[[:space:]]*/) {
          sub(/^[[:space:]]*[^[:space:]]+[.]go:[0-9]+:[[:space:]]*/, "", reason_line)
          reason = reason_line
        } else if (reason_line !~ /^[[:space:]]*$/) reason = reason "\n" reason_line
      }
      class = classify(package, test, reason)
      counts[class]++
      if (class == "capability") {
        capability_message = message
        gsub(/[\r\n]+/, " ", capability_message)
        capability_rows[++capability_count] = "- `" package " / " test "`: " capability_message
      }
      printf "test-skips: %s %s %s\n%s", class, package, test, message
      if (message == "" || substr(message, length(message), 1) != "\n") printf "\n"
      if (class != "GOOS") rejected++
    }
    delete output[key]
  } else if (action == "pass" || action == "fail") delete output[key]
}
END {
  summary_line("\n### Go test skips")
  summary_line("| Class | Count |")
  summary_line("|---|---:|")
  for (n = 1; n <= 5; n++) summary_line(sprintf("| %s | %d |", classes[n], counts[classes[n]]))
  summary_line(sprintf("| no test files (packages) | %d |", no_test_files))
  summary_line(sprintf("| other package skips | %d |", package_skips))
  summary_line(sprintf("test-skips: enforce=%d non-GOOS=%d invalid-events=%d", enforce, rejected, errors))
  if (capability_count) {
    summary_line("\n#### Capability skips")
    for (n = 1; n <= capability_count; n++) summary_line(capability_rows[n])
  }
  if (errors) exit 2
  if (enforce && rejected) exit 1
}
'
