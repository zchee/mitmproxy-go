// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package imagemeta

import (
	"encoding/binary"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/internal/testutil"
)

// TestParseJPEG ports upstream's test_parse_jpeg table.
func TestParseJPEG(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		fixture string
		want    [][2]string
	}{
		"success: app0": {
			fixture: "mitmproxy/image_parser/example.jpg",
			want: [][2]string{
				{"Format", "JPEG (ISO 10918)"},
				{"jfif_version", "(1, 1)"},
				{"jfif_density", "(96, 96)"},
				{"jfif_unit", "1"},
				{"Size", "256 x 256 px"},
			},
		},
		"success: com": {
			fixture: "mitmproxy/image_parser/comment.jpg",
			want: [][2]string{
				{"Format", "JPEG (ISO 10918)"},
				{"jfif_version", "(1, 1)"},
				{"jfif_density", "(96, 96)"},
				{"jfif_unit", "1"},
				{"comment", "mitmproxy test image"},
				{"Size", "256 x 256 px"},
			},
		},
		"success: app1": {
			fixture: "mitmproxy/image_parser/app1.jpeg",
			want: [][2]string{
				{"Format", "JPEG (ISO 10918)"},
				{"jfif_version", "(1, 1)"},
				{"jfif_density", "(72, 72)"},
				{"jfif_unit", "1"},
				{"make", "Canon"},
				{"model", "Canon PowerShot A60"},
				{"modify_date", "2004:07:16 18:46:04"},
				{"Size", "717 x 558 px"},
			},
		},
		"success: multiple segments": {
			fixture: "mitmproxy/image_parser/all.jpeg",
			want: [][2]string{
				{"Format", "JPEG (ISO 10918)"},
				{"jfif_version", "(1, 1)"},
				{"jfif_density", "(300, 300)"},
				{"jfif_unit", "1"},
				{"comment", allJPEGComment},
				{"Size", "750 x 1055 px"},
			},
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got, err := ParseJPEG(testutil.Fixture(t, tt.fixture))
			if err != nil {
				t.Fatalf("ParseJPEG() error = %v", err)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Fatalf("metadata (-want +got):\n%s", diff)
			}
		})
	}
}

// allJPEGComment is the comment segment of all.jpeg; its \xe8 spells the
// one non-UTF-8 byte the way Python's backslashreplace handler writes it.
const allJPEGComment = "BARTOLOMEO DI FRUOSINO\r\n(b. ca. 1366, Firenze, d. 1441, " +
	"Firenze)\r\n\r\nInferno, from the Divine Comedy by Dante (Folio 1v)" +
	"\r\n1430-35\r\nTempera, gold, and silver on parchment, 365 x 265 mm" +
	"\r\nBiblioth" + `\xe8` + "que Nationale, Paris\r\n\r\nThe codex in Paris " +
	"contains the text of the Inferno, the first of three books of the Divine " +
	"Comedy, the masterpiece of the Florentine poet Dante Alighieri (1265-1321)." +
	" The codex begins with two full-page illuminations. On folio 1v Dante and " +
	"Virgil stand within the doorway of Hell at the upper left and observe its " +
	"nine different zones. Dante and Virgil are to wade through successive " +
	"circles teeming with images of the damned. The gates of Hell appear  in " +
	"the middle, a scarlet row of open sarcophagi before them. Devils orchestrate" +
	" the movements of the wretched souls.\r\n\r\nThe vision of the fiery " +
	`inferno follows a convention established by <A onclick="return OpenOther` +
	`('/html/n/nardo/strozzi3.html')" HREF="/html/n/nardo/strozzi3.html">` +
	"Nardo di Cione's fresco</A> in the church of Santa Maria Novella, Florence." +
	" Of remarkable vivacity and intensity of expression, the illumination is " +
	"executed in Bartolomeo's late style.\r\n\r\n\r\n\r\n\r\n\r\n\r\n" +
	"--- Keywords: --------------\r\n\r\nAuthor: BARTOLOMEO DI FRUOSINO" +
	"\r\nTitle: Inferno, from the Divine Comedy by Dante (Folio 1v)\r\nTime-line:" +
	" 1401-1450\r\nSchool: Italian\r\nForm: illumination\r\nType: other\r\n"

// jpegSegment frames body as a segment with the given marker.
func jpegSegment(marker byte, body []byte) []byte {
	out := []byte{0xff, marker}
	out = binary.BigEndian.AppendUint16(out, uint16(len(body)+2))
	return append(out, body...)
}

// jpegFile frames segments between start-of-image and end-of-image markers.
func jpegFile(segments ...[]byte) []byte {
	out := []byte{0xff, 0xd8}
	for _, segment := range segments {
		out = append(out, segment...)
	}
	return append(out, 0xff, 0xd9)
}

// jpegAPP0 frames a JFIF application segment with the given density unit.
func jpegAPP0(unit byte) []byte {
	body := []byte("JFIF\x00\x01\x02")
	body = append(body, unit)
	body = binary.BigEndian.AppendUint16(body, 96)
	body = binary.BigEndian.AppendUint16(body, 48)
	return jpegSegment(0xe0, append(body, 0, 0))
}

// exifAPP1 frames an Exif application segment holding one little-endian
// IFD field of the given tag and external data.
func exifAPP1(tag uint16, data []byte) []byte {
	tiff := []byte("II\x2a\x00\x08\x00\x00\x00")
	tiff = binary.LittleEndian.AppendUint16(tiff, 1) // one field
	tiff = binary.LittleEndian.AppendUint16(tiff, tag)
	tiff = binary.LittleEndian.AppendUint16(tiff, 2) // ASCII
	tiff = binary.LittleEndian.AppendUint32(tiff, uint32(len(data)))
	tiff = binary.LittleEndian.AppendUint32(tiff, 26) // past the next-IFD offset
	tiff = binary.LittleEndian.AppendUint32(tiff, 0)  // next IFD
	tiff = append(tiff, data...)
	return jpegSegment(0xe1, append([]byte("Exif\x00\x00"), tiff...))
}

// TestParseJPEGMalformed exercises the segment and Exif error paths.
func TestParseJPEGMalformed(t *testing.T) {
	t.Parallel()
	jfifRows := [][2]string{
		{"Format", "JPEG (ISO 10918)"},
		{"jfif_version", "(1, 2)"},
		{"jfif_density", "(96, 48)"},
		{"jfif_unit", "1"},
	}
	tests := map[string]struct {
		data []byte
		want [][2]string
	}{
		"error: segment without its magic byte": {
			data: []byte{0xff, 0xd8, 0xe0, 0x00},
		},
		"error: marker outside the enumeration": {
			data: []byte{0xff, 0xd8, 0xff, 0xd0, 0x00, 0x02},
		},
		"error: segment length shorter than its own field": {
			data: []byte{0xff, 0xd8, 0xff, 0xe0, 0x00, 0x01},
		},
		"error: segment body cut short": {
			data: []byte{0xff, 0xd8, 0xff, 0xfe, 0x00, 0x08, 'h', 'i'},
		},
		"error: app0 magic is not ASCII": {
			data: jpegFile(jpegSegment(0xe0, []byte("JF\xc9F\x00\x01\x02\x01\x00\x60\x00\x30\x00\x00"))),
		},
		"error: density unit outside the enumeration": {
			data: jpegFile(jpegAPP0(3)),
		},
		"error: app0 thumbnail cut short": {
			data: jpegFile(jpegSegment(0xe0, []byte("JFIF\x00\x01\x02\x01\x00\x60\x00\x30\x01\x01"))),
		},
		"error: sof0 component list cut short": {
			data: jpegFile(jpegSegment(0xc0, []byte{8, 0x01, 0x00, 0x02, 0x00, 3, 1, 2})),
		},
		"error: app1 magic without terminator": {
			data: jpegFile(jpegSegment(0xe1, []byte("Exif"))),
		},
		"error: exif without padding byte": {
			data: jpegFile(jpegSegment(0xe1, []byte("Exif\x00II"))),
		},
		"error: exif endianness unknown": {
			data: jpegFile(jpegSegment(0xe1, []byte("Exif\x00\x00XX\x2a\x00\x08\x00\x00\x00"))),
		},
		"error: exif IFD offset past the end": {
			data: jpegFile(jpegSegment(0xe1, []byte("Exif\x00\x00II\x2a\x00\xff\x00\x00\x00"))),
		},
		"error: exif tag outside the table": {
			data: jpegFile(exifAPP1(3, []byte("Hello\x00"))),
		},
		"error: exif value is not UTF-8": {
			data: jpegFile(exifAPP1(271, []byte("Can\xffn\x00"))),
		},
		"error: exif data past the end": {
			data: jpegFile(jpegSegment(0xe1, append([]byte("Exif\x00\x00II\x2a\x00\x08\x00\x00\x00"),
				0x01, 0x00, // one field
				0x0f, 0x01, // make
				0x02, 0x00, // ASCII
				0x40, 0x00, 0x00, 0x00, // 64 bytes, longer than the segment
				0x1a, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00))), // next IFD
		},
		"success: exif text field": {
			data: jpegFile(exifAPP1(271, []byte("Canon\x00"))),
			want: [][2]string{
				{"Format", "JPEG (ISO 10918)"},
				{"make", "Canon"},
			},
		},
		"success: inline exif value is skipped without naming the tag": {
			data: jpegFile(jpegSegment(0xe1, append([]byte("Exif\x00\x00II\x2a\x00\x08\x00\x00\x00"),
				0x01, 0x00, // one field
				0x03, 0x00, // unknown tag 3
				0x02, 0x00, // ASCII
				0x04, 0x00, 0x00, 0x00, // four bytes fit inline
				'A', 'B', 'C', 0x00,
				0x00, 0x00, 0x00, 0x00))), // next IFD
			want: [][2]string{{"Format", "JPEG (ISO 10918)"}},
		},
		"success: non-Exif app1 is skipped": {
			data: jpegFile(jpegSegment(0xe1, []byte("http://ns.adobe.com/xap/1.0/\x00<x/>"))),
			want: [][2]string{{"Format", "JPEG (ISO 10918)"}},
		},
		"success: comment keeps undecodable bytes as escapes": {
			data: jpegFile(jpegSegment(0xfe, []byte("caf\xe9"))),
			want: [][2]string{
				{"Format", "JPEG (ISO 10918)"},
				{"comment", `caf\xe9`},
			},
		},
		"success: bytes after start of scan are image data": {
			data: append(jpegFile(jpegSegment(0xda, []byte{1, 1, 0, 0, 63, 0})), "entropy-coded, not segments"...),
			want: [][2]string{{"Format", "JPEG (ISO 10918)"}},
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got, err := ParseJPEG(tt.data)
			if (err != nil) != (tt.want == nil) {
				t.Fatalf("ParseJPEG() = %v, error = %v; want error %t", got, err, tt.want == nil)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Fatalf("metadata (-want +got):\n%s", diff)
			}
		})
	}
	t.Run("success: density unit row uses the crafted header", func(t *testing.T) {
		t.Parallel()
		got, err := ParseJPEG(jpegFile(jpegAPP0(1)))
		if err != nil {
			t.Fatalf("ParseJPEG() error = %v", err)
		}
		if diff := cmp.Diff(jfifRows, got); diff != "" {
			t.Fatalf("metadata (-want +got):\n%s", diff)
		}
	})
}

// TestParseJPEGTruncated feeds the parser every prefix of a fixture: no
// prefix may panic, and only a cut at a segment boundary may succeed.
func TestParseJPEGTruncated(t *testing.T) {
	t.Parallel()
	data := testutil.Fixture(t, "mitmproxy/image_parser/example.jpg")
	for i := range len(data) {
		if _, err := ParseJPEG(data[:i]); err == nil && !atJPEGSegmentBoundary(data, i) {
			t.Fatalf("ParseJPEG(data[:%d]) succeeded inside a segment", i)
		}
	}
}

// atJPEGSegmentBoundary reports whether a cut at offset i of a well-formed
// JPEG file may parse: exactly between segments, or anywhere after the
// start-of-scan segment, whose image data runs to the end of the file.
func atJPEGSegmentBoundary(data []byte, i int) bool {
	pos := 0
	for pos < i {
		marker := data[pos+1]
		if marker == 0xd8 || marker == 0xd9 {
			pos += 2
			continue
		}
		next := pos + 2 + int(binary.BigEndian.Uint16(data[pos+2:]))
		if marker == 0xda {
			return i >= next
		}
		pos = next
	}
	return pos == i
}
