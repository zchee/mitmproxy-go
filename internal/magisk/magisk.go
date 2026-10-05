// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package magisk builds the Magisk module archive that installs the mitmproxy
// CA certificate into Android's system certificate store, as
// mitmproxy/utils/magisk.py builds it.
package magisk

import (
	"archive/zip"
	"crypto/md5" //nolint:gosec // OpenSSL defines subject_hash_old over MD5; the digest names a file and protects nothing.
	"crypto/x509"
	"fmt"
	"io"
	"strconv"
)

// moduleProp is the module.prop entry, byte for byte as upstream writes it.
const moduleProp = `id=mitmproxycert
name=MITMProxy cert
version=v1
versionCode=1
author=mitmproxy
description=Adds the mitmproxy certificate to the system store
template=3`

// configSH is the config.sh entry, byte for byte as upstream writes it,
// including the leading blank line.
const configSH = `
MODID=mitmproxycert
AUTOMOUNT=true
PROPFILE=false
POSTFSDATA=false
LATESTARTSERVICE=false

print_modname() {
  ui_print "*******************************"
  ui_print "    MITMProxy cert installer   "
  ui_print "*******************************"
}

REPLACE="
"

set_permissions() {
  set_perm_recursive  $MODPATH  0  0  0755  0644
}
`

// updateBinary is the META-INF update-binary entry, byte for byte as upstream
// writes it, including the leading blank line.
const updateBinary = `
#!/sbin/sh

#################
# Initialization
#################

umask 022

# echo before loading util_functions
ui_print() { echo "$1"; }

require_new_magisk() {
  ui_print "*******************************"
  ui_print " Please install Magisk v20.4+! "
  ui_print "*******************************"
  exit 1
}

OUTFD=$2
ZIPFILE=$3

mount /data 2>/dev/null
[ -f /data/adb/magisk/util_functions.sh ] || require_new_magisk
. /data/adb/magisk/util_functions.sh
[ $MAGISK_VER_CODE -lt 20400 ] && require_new_magisk

install_module
exit 0
`

// SubjectHashOld returns the hash OpenSSL's -subject_hash_old option prints
// for the certificate: the first four bytes of the MD5 digest of the
// DER-encoded subject name read as a little-endian integer, formatted as
// lowercase hexadecimal without leading zeros. Android names system CA
// certificate files after this hash.
func SubjectHashOld(ca *x509.Certificate) string {
	digest := md5.Sum(ca.RawSubject) //nolint:gosec // OpenSSL's subject_hash_old is MD5 by definition; it names a file.
	value := uint32(digest[0]) | uint32(digest[1])<<8 | uint32(digest[2])<<16 | uint32(digest[3])<<24
	return strconv.FormatUint(uint64(value), 16)
}

// WriteModule writes to w the Magisk module zip that installs ca into the
// system certificate store: the DER certificate under
// system/etc/security/cacerts/<SubjectHashOld>.0 and the fixed module files,
// in upstream's entry order.
func WriteModule(w io.Writer, ca *x509.Certificate) error {
	entries := [...]struct{ name, content string }{
		{"system/etc/security/cacerts/" + SubjectHashOld(ca) + ".0", string(ca.Raw)},
		{"module.prop", moduleProp},
		{"config.sh", configSH},
		{"META-INF/com/google/android/updater-script", "#MAGISK"},
		{"META-INF/com/google/android/update-binary", updateBinary},
		{"common/file_contexts_image", "/magisk(/.*)? u:object_r:system_file:s0"},
		{"common/post-fs-data.sh", "MODDIR=${0%/*}"},
		{"common/service.sh", "MODDIR=${0%/*}"},
		{"common/system.prop", ""},
	}
	zw := zip.NewWriter(w)
	for _, e := range entries {
		f, err := zw.Create(e.name)
		if err != nil {
			return fmt.Errorf("magisk: create %s: %w", e.name, err)
		}
		if _, err := io.WriteString(f, e.content); err != nil {
			return fmt.Errorf("magisk: write %s: %w", e.name, err)
		}
	}
	if err := zw.Close(); err != nil {
		return fmt.Errorf("magisk: close archive: %w", err)
	}
	return nil
}
