// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package dns

import (
	"fmt"
	"strconv"
	"strings"
)

// DNS resource record types, from the IANA DNS parameters registry as
// upstream lists them.
const (
	TypeA          = 1
	TypeNS         = 2
	TypeMD         = 3
	TypeMF         = 4
	TypeCNAME      = 5
	TypeSOA        = 6
	TypeMB         = 7
	TypeMG         = 8
	TypeMR         = 9
	TypeNULL       = 10
	TypeWKS        = 11
	TypePTR        = 12
	TypeHINFO      = 13
	TypeMINFO      = 14
	TypeMX         = 15
	TypeTXT        = 16
	TypeRP         = 17
	TypeAFSDB      = 18
	TypeX25        = 19
	TypeISDN       = 20
	TypeRT         = 21
	TypeNSAP       = 22
	TypeNSAPPTR    = 23
	TypeSIG        = 24
	TypeKEY        = 25
	TypePX         = 26
	TypeGPOS       = 27
	TypeAAAA       = 28
	TypeLOC        = 29
	TypeNXT        = 30
	TypeEID        = 31
	TypeNIMLOC     = 32
	TypeSRV        = 33
	TypeATMA       = 34
	TypeNAPTR      = 35
	TypeKX         = 36
	TypeCERT       = 37
	TypeA6         = 38
	TypeDNAME      = 39
	TypeSINK       = 40
	TypeOPT        = 41
	TypeAPL        = 42
	TypeDS         = 43
	TypeSSHFP      = 44
	TypeIPSECKEY   = 45
	TypeRRSIG      = 46
	TypeNSEC       = 47
	TypeDNSKEY     = 48
	TypeDHCID      = 49
	TypeNSEC3      = 50
	TypeNSEC3PARAM = 51
	TypeTLSA       = 52
	TypeSMIMEA     = 53
	TypeHIP        = 55
	TypeNINFO      = 56
	TypeRKEY       = 57
	TypeTALINK     = 58
	TypeCDS        = 59
	TypeCDNSKEY    = 60
	TypeOPENPGPKEY = 61
	TypeCSYNC      = 62
	TypeZONEMD     = 63
	TypeSVCB       = 64
	TypeHTTPS      = 65
	TypeSPF        = 99
	TypeUINFO      = 100
	TypeUID        = 101
	TypeGID        = 102
	TypeUNSPEC     = 103
	TypeNID        = 104
	TypeL32        = 105
	TypeL64        = 106
	TypeLP         = 107
	TypeEUI48      = 108
	TypeEUI64      = 109
	TypeTKEY       = 249
	TypeTSIG       = 250
	TypeIXFR       = 251
	TypeAXFR       = 252
	TypeMAILB      = 253
	TypeMAILA      = 254
	TypeANY        = 255
	TypeURI        = 256
	TypeCAA        = 257
	TypeAVC        = 258
	TypeDOA        = 259
	TypeAMTRELAY   = 260
	TypeTA         = 32768
	TypeDLV        = 32769
)

var typeNames = map[int]string{
	TypeA:          "A",
	TypeNS:         "NS",
	TypeMD:         "MD",
	TypeMF:         "MF",
	TypeCNAME:      "CNAME",
	TypeSOA:        "SOA",
	TypeMB:         "MB",
	TypeMG:         "MG",
	TypeMR:         "MR",
	TypeNULL:       "NULL",
	TypeWKS:        "WKS",
	TypePTR:        "PTR",
	TypeHINFO:      "HINFO",
	TypeMINFO:      "MINFO",
	TypeMX:         "MX",
	TypeTXT:        "TXT",
	TypeRP:         "RP",
	TypeAFSDB:      "AFSDB",
	TypeX25:        "X25",
	TypeISDN:       "ISDN",
	TypeRT:         "RT",
	TypeNSAP:       "NSAP",
	TypeNSAPPTR:    "NSAP_PTR",
	TypeSIG:        "SIG",
	TypeKEY:        "KEY",
	TypePX:         "PX",
	TypeGPOS:       "GPOS",
	TypeAAAA:       "AAAA",
	TypeLOC:        "LOC",
	TypeNXT:        "NXT",
	TypeEID:        "EID",
	TypeNIMLOC:     "NIMLOC",
	TypeSRV:        "SRV",
	TypeATMA:       "ATMA",
	TypeNAPTR:      "NAPTR",
	TypeKX:         "KX",
	TypeCERT:       "CERT",
	TypeA6:         "A6",
	TypeDNAME:      "DNAME",
	TypeSINK:       "SINK",
	TypeOPT:        "OPT",
	TypeAPL:        "APL",
	TypeDS:         "DS",
	TypeSSHFP:      "SSHFP",
	TypeIPSECKEY:   "IPSECKEY",
	TypeRRSIG:      "RRSIG",
	TypeNSEC:       "NSEC",
	TypeDNSKEY:     "DNSKEY",
	TypeDHCID:      "DHCID",
	TypeNSEC3:      "NSEC3",
	TypeNSEC3PARAM: "NSEC3PARAM",
	TypeTLSA:       "TLSA",
	TypeSMIMEA:     "SMIMEA",
	TypeHIP:        "HIP",
	TypeNINFO:      "NINFO",
	TypeRKEY:       "RKEY",
	TypeTALINK:     "TALINK",
	TypeCDS:        "CDS",
	TypeCDNSKEY:    "CDNSKEY",
	TypeOPENPGPKEY: "OPENPGPKEY",
	TypeCSYNC:      "CSYNC",
	TypeZONEMD:     "ZONEMD",
	TypeSVCB:       "SVCB",
	TypeHTTPS:      "HTTPS",
	TypeSPF:        "SPF",
	TypeUINFO:      "UINFO",
	TypeUID:        "UID",
	TypeGID:        "GID",
	TypeUNSPEC:     "UNSPEC",
	TypeNID:        "NID",
	TypeL32:        "L32",
	TypeL64:        "L64",
	TypeLP:         "LP",
	TypeEUI48:      "EUI48",
	TypeEUI64:      "EUI64",
	TypeTKEY:       "TKEY",
	TypeTSIG:       "TSIG",
	TypeIXFR:       "IXFR",
	TypeAXFR:       "AXFR",
	TypeMAILB:      "MAILB",
	TypeMAILA:      "MAILA",
	TypeANY:        "ANY",
	TypeURI:        "URI",
	TypeCAA:        "CAA",
	TypeAVC:        "AVC",
	TypeDOA:        "DOA",
	TypeAMTRELAY:   "AMTRELAY",
	TypeTA:         "TA",
	TypeDLV:        "DLV",
}

// TypeToString returns the name of a type, or "TYPE(n)" for an
// unknown value, as upstream's to_str does.
func TypeToString(v int) string {
	if s, ok := typeNames[v]; ok {
		return s
	}
	return "TYPE(" + strconv.Itoa(v) + ")"
}

// TypeFromString parses a name produced by TypeToString.
func TypeFromString(s string) (int, error) {
	return fromString(s, "TYPE", typeNames)
}

// DNS classes.
const (
	ClassIN   = 1
	ClassCH   = 3
	ClassHS   = 4
	ClassNONE = 254
	ClassANY  = 255
)

var classNames = map[int]string{
	ClassIN:   "IN",
	ClassCH:   "CH",
	ClassHS:   "HS",
	ClassNONE: "NONE",
	ClassANY:  "ANY",
}

// ClassToString returns the name of a class, or "CLASS(n)" for an
// unknown value, as upstream's to_str does.
func ClassToString(v int) string {
	if s, ok := classNames[v]; ok {
		return s
	}
	return "CLASS(" + strconv.Itoa(v) + ")"
}

// ClassFromString parses a name produced by ClassToString.
func ClassFromString(s string) (int, error) {
	return fromString(s, "CLASS", classNames)
}

// DNS operation codes.
const (
	OpCodeQUERY  = 0
	OpCodeIQUERY = 1
	OpCodeSTATUS = 2
	OpCodeNOTIFY = 4
	OpCodeUPDATE = 5
	OpCodeDSO    = 6
)

var opCodeNames = map[int]string{
	OpCodeQUERY:  "QUERY",
	OpCodeIQUERY: "IQUERY",
	OpCodeSTATUS: "STATUS",
	OpCodeNOTIFY: "NOTIFY",
	OpCodeUPDATE: "UPDATE",
	OpCodeDSO:    "DSO",
}

// OpCodeToString returns the name of a op code, or "OPCODE(n)" for an
// unknown value, as upstream's to_str does.
func OpCodeToString(v int) string {
	if s, ok := opCodeNames[v]; ok {
		return s
	}
	return "OPCODE(" + strconv.Itoa(v) + ")"
}

// OpCodeFromString parses a name produced by OpCodeToString.
func OpCodeFromString(s string) (int, error) {
	return fromString(s, "OPCODE", opCodeNames)
}

// DNS response codes.
const (
	ResponseCodeNOERROR   = 0
	ResponseCodeFORMERR   = 1
	ResponseCodeSERVFAIL  = 2
	ResponseCodeNXDOMAIN  = 3
	ResponseCodeNOTIMP    = 4
	ResponseCodeREFUSED   = 5
	ResponseCodeYXDOMAIN  = 6
	ResponseCodeYXRRSET   = 7
	ResponseCodeNXRRSET   = 8
	ResponseCodeNOTAUTH   = 9
	ResponseCodeNOTZONE   = 10
	ResponseCodeDSOTYPENI = 11
)

var responseCodeNames = map[int]string{
	ResponseCodeNOERROR:   "NOERROR",
	ResponseCodeFORMERR:   "FORMERR",
	ResponseCodeSERVFAIL:  "SERVFAIL",
	ResponseCodeNXDOMAIN:  "NXDOMAIN",
	ResponseCodeNOTIMP:    "NOTIMP",
	ResponseCodeREFUSED:   "REFUSED",
	ResponseCodeYXDOMAIN:  "YXDOMAIN",
	ResponseCodeYXRRSET:   "YXRRSET",
	ResponseCodeNXRRSET:   "NXRRSET",
	ResponseCodeNOTAUTH:   "NOTAUTH",
	ResponseCodeNOTZONE:   "NOTZONE",
	ResponseCodeDSOTYPENI: "DSOTYPENI",
}

// ResponseCodeToString returns the name of a response code, or "RCODE(n)" for an
// unknown value, as upstream's to_str does.
func ResponseCodeToString(v int) string {
	if s, ok := responseCodeNames[v]; ok {
		return s
	}
	return "RCODE(" + strconv.Itoa(v) + ")"
}

// ResponseCodeFromString parses a name produced by ResponseCodeToString.
func ResponseCodeFromString(s string) (int, error) {
	return fromString(s, "RCODE", responseCodeNames)
}

var httpEquivStatusCodes = map[int]int{
	ResponseCodeNOERROR:   200,
	ResponseCodeFORMERR:   400,
	ResponseCodeSERVFAIL:  500,
	ResponseCodeNXDOMAIN:  404,
	ResponseCodeNOTIMP:    501,
	ResponseCodeREFUSED:   403,
	ResponseCodeYXDOMAIN:  409,
	ResponseCodeYXRRSET:   409,
	ResponseCodeNXRRSET:   410,
	ResponseCodeNOTAUTH:   401,
	ResponseCodeNOTZONE:   404,
	ResponseCodeDSOTYPENI: 501,
}

// HTTPEquivStatusCode maps a response code to the HTTP status code with the
// closest meaning, 500 for unknown codes, as upstream does for display.
func HTTPEquivStatusCode(rcode int) int {
	if c, ok := httpEquivStatusCodes[rcode]; ok {
		return c
	}
	return 500
}

// fromString looks name up in names, or parses the "PREFIX(n)" form.
func fromString(name, prefix string, names map[int]string) (int, error) {
	for v, n := range names {
		if n == name {
			return v, nil
		}
	}
	s := strings.TrimSuffix(strings.TrimPrefix(name, prefix+"("), ")")
	v, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("invalid %s name %q", strings.ToLower(prefix), name)
	}
	return v, nil
}
