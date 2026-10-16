// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package processinfo

import (
	"errors"
	"image"
)

func colorIcon(bgra, mask []byte, width, height int) (*image.RGBA, error) {
	length, err := nativeBufferSize(width, height, width*4)
	if err != nil {
		return nil, err
	}
	if len(bgra) != length || (len(mask) != 0 && len(mask) != length) {
		return nil, errors.New("processinfo: inconsistent icon pixel length")
	}
	hasAlpha := false
	for offset := 3; offset < length; offset += 4 {
		hasAlpha = hasAlpha || bgra[offset] != 0
	}
	result := image.NewRGBA(image.Rect(0, 0, width, height))
	for offset := 0; offset < length; offset += 4 {
		alpha := bgra[offset+3]
		if !hasAlpha {
			alpha = 255
			if len(mask) != 0 && mask[offset] != 0 {
				alpha = 0
			}
		}
		if alpha != 0 {
			result.Pix[offset] = bgra[offset+2]
			result.Pix[offset+1] = bgra[offset+1]
			result.Pix[offset+2] = bgra[offset]
			result.Pix[offset+3] = alpha
		}
	}
	return result, nil
}

func monochromeIcon(mask []byte, width, height int) (*image.RGBA, error) {
	length, err := nativeBufferSize(width, height, width*4)
	if err != nil {
		return nil, err
	}
	if height%2 != 0 || len(mask) != length {
		return nil, errors.New("processinfo: inconsistent monochrome icon planes")
	}
	result := image.NewRGBA(image.Rect(0, 0, width, height/2))
	for offset := 0; offset < length/2; offset += 4 {
		andBit := mask[offset] != 0
		xorBit := mask[offset+length/2] != 0
		if andBit && xorBit {
			return nil, errors.New("processinfo: destination-inverting icon has no PNG equivalent")
		}
		if !andBit {
			if xorBit {
				result.Pix[offset], result.Pix[offset+1], result.Pix[offset+2] = 255, 255, 255
			}
			result.Pix[offset+3] = 255
		}
	}
	return result, nil
}
