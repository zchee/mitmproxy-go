// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package contentviews

import (
	"bytes"
	"strings"

	"github.com/zchee/mitmproxy-go/contentviews/imagemeta"
)

// Image displays an image's metadata as YAML under a heading that names
// the detected format.
type Image struct{}

// Name returns the registered view name.
func (Image) Name() string { return "Image" }

// SyntaxHighlight returns the view's highlighting language.
func (Image) SyntaxHighlight() string { return "yaml" }

// RenderPriority prefers image content types other than SVG.
func (Image) RenderPriority(data []byte, metadata Metadata) float64 {
	if strings.HasPrefix(metadata.ContentType, "image/") && !strings.HasSuffix(metadata.ContentType, "+xml") {
		return 1
	}
	return 0
}

// Prettify names the detected image format and lists the metadata of a
// PNG, GIF, JPEG or ICO image. It returns an error when such an image is
// malformed; a format it detects but cannot parse gets the heading alone.
func (Image) Prettify(data []byte, metadata Metadata) (string, error) {
	kind := imageType(data)
	var pairs [][2]string
	var err error
	switch kind {
	case "png":
		pairs, err = imagemeta.ParsePNG(data)
	case "gif":
		pairs, err = imagemeta.ParseGIF(data)
	case "jpeg":
		pairs, err = imagemeta.ParseJPEG(data)
	case "ico":
		pairs, err = imagemeta.ParseICO(data)
	}
	if err != nil {
		return "", err
	}
	heading := "# Unknown Image\n"
	if kind != "" {
		heading = "# " + strings.ToUpper(kind) + " Image\n"
	}
	body, err := yamlPairs(pairs)
	if err != nil {
		return "", err
	}
	return heading + body, nil
}

// imageType names the image format of the first 32 bytes of data, with
// the tests and order of the imghdr module mitmproxy vendors, or returns
// an empty string. The ICO test the upstream view appends comes last.
func imageType(data []byte) string {
	h := data
	if len(h) > 32 {
		h = h[:32]
	}
	switch {
	case len(h) >= 10 && (string(h[6:10]) == "JFIF" || string(h[6:10]) == "Exif"),
		bytes.HasPrefix(h, []byte("\xff\xd8\xff\xdb")):
		return "jpeg"
	case bytes.HasPrefix(h, []byte("\x89PNG\r\n\x1a\n")):
		return "png"
	case len(h) >= 6 && (string(h[:6]) == "GIF87a" || string(h[:6]) == "GIF89a"):
		return "gif"
	case bytes.HasPrefix(h, []byte("MM")), bytes.HasPrefix(h, []byte("II")):
		return "tiff"
	case bytes.HasPrefix(h, []byte("\x01\xda")):
		return "rgb"
	case len(h) >= 3 && h[0] == 'P' && (h[1] == '1' || h[1] == '4') && isPNMSeparator(h[2]):
		return "pbm"
	case len(h) >= 3 && h[0] == 'P' && (h[1] == '2' || h[1] == '5') && isPNMSeparator(h[2]):
		return "pgm"
	case len(h) >= 3 && h[0] == 'P' && (h[1] == '3' || h[1] == '6') && isPNMSeparator(h[2]):
		return "ppm"
	case bytes.HasPrefix(h, []byte("\x59\xa6\x6a\x95")):
		return "rast"
	case bytes.HasPrefix(h, []byte("#define ")):
		return "xbm"
	case bytes.HasPrefix(h, []byte("BM")):
		return "bmp"
	case len(h) >= 12 && string(h[:4]) == "RIFF" && string(h[8:12]) == "WEBP":
		return "webp"
	case bytes.HasPrefix(h, []byte("\x76\x2f\x31\x01")):
		return "exr"
	case bytes.HasPrefix(h, []byte("\x00\x00\x01\x00")):
		return "ico"
	default:
		return ""
	}
}

// isPNMSeparator reports whether c separates a PNM magic number from the
// image dimensions.
func isPNMSeparator(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r'
}
