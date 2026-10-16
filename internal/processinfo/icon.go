// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package processinfo

import (
	"bytes"
	"fmt"
	"image"
	"image/png"

	"golang.org/x/image/draw"
)

const (
	maxIconDimension = 4096
	maxNativeBytes   = 64 << 20
	maxPNGBytes      = 1 << 20
	iconEdge         = 32
)

func iconSize(width, height int) (int, int, error) {
	if width <= 0 || height <= 0 || width > maxIconDimension || height > maxIconDimension {
		return 0, 0, fmt.Errorf("processinfo: icon dimensions %dx%d outside 1..%d", width, height, maxIconDimension)
	}
	if width >= height {
		return iconEdge, max(1, (height*iconEdge+width/2)/width), nil
	}
	return max(1, (width*iconEdge+height/2)/height), iconEdge, nil
}

func nativeBufferSize(width, height, stride int) (int, error) {
	if _, _, err := iconSize(width, height); err != nil {
		return 0, err
	}
	if stride < width*4 || stride > maxNativeBytes/height {
		return 0, fmt.Errorf("processinfo: icon stride %d exceeds native buffer bounds", stride)
	}
	return stride * height, nil
}

func iconPNG(source image.Image) ([]byte, error) {
	bounds := source.Bounds()
	width, height, err := iconSize(bounds.Dx(), bounds.Dy())
	if err != nil {
		return nil, err
	}
	resized := image.NewRGBA(image.Rect(0, 0, width, height))
	draw.BiLinear.Scale(resized, resized.Bounds(), source, bounds, draw.Src, nil)
	output := boundedPNG{limit: maxPNGBytes}
	if err := png.Encode(&output, resized); err != nil {
		return nil, fmt.Errorf("processinfo: encode icon: %w", err)
	}
	return output.Bytes(), nil
}

type boundedPNG struct {
	bytes.Buffer
	limit int
}

func (w *boundedPNG) Write(data []byte) (int, error) {
	if len(data) > w.limit-w.Len() {
		return 0, fmt.Errorf("processinfo: PNG exceeds %d bytes", w.limit)
	}
	return w.Buffer.Write(data)
}
