// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build darwin

package processinfo

import (
	"errors"
	"fmt"
	"image"
	"os"
	"strings"
	"unicode/utf8"
	"unsafe"

	"github.com/ebitengine/purego/objc"
)

var darwinIcons = newIconCache(256, 16<<20)

// ExecutableIcon returns a caller-owned PNG fitting within 32 by 32 pixels.
func ExecutableIcon(path string) ([]byte, error) {
	return darwinIcons.get(path, darwinIcon)
}

func darwinIcon(path string) ([]byte, error) {
	if strings.IndexByte(path, 0) >= 0 || !utf8.ValidString(path) {
		return nil, errors.New("processinfo: executable path is not valid native UTF-8")
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("processinfo: executable: %w", err)
	}
	if info.IsDir() {
		return nil, errors.New("processinfo: executable path is a directory")
	}
	var pixels *image.RGBA
	err = withDarwinPool(func(api *darwinNative) error {
		workspace := objc.ID(api.workspaceClass).Send(api.sharedWorkspace)
		if workspace == 0 {
			return errors.New("processinfo: shared workspace unavailable")
		}
		var source objc.ID
		applications := workspace.Send(api.runningApps)
		if applications != 0 {
			count := objc.Send[uint64](applications, api.count)
			for index := range count {
				application := applications.Send(api.objectAtIndex, index)
				url := application.Send(api.executableURL)
				if url == 0 {
					continue
				}
				nativePath := url.Send(api.path)
				if nativePath != 0 && objc.Send[string](nativePath, api.utf8String) == path {
					source = application.Send(api.icon)
					if source != 0 {
						break
					}
				}
			}
		}
		if source == 0 {
			nativePath := objc.ID(api.stringClass).Send(api.stringWithUTF8, path)
			if nativePath == 0 {
				return errors.New("processinfo: create executable path string")
			}
			source = workspace.Send(api.iconForFile, nativePath)
		}
		if source == 0 {
			return errors.New("processinfo: executable icon unavailable")
		}
		var err error
		pixels, err = renderDarwinImage(api, source)
		return err
	})
	if err != nil {
		return nil, err
	}
	return iconPNG(pixels)
}

func renderDarwinImage(api *darwinNative, source objc.ID) (*image.RGBA, error) {
	if source == 0 {
		return nil, errors.New("processinfo: missing native image")
	}
	nativeImage := objc.Send[uintptr](source, api.cgImage, (*cgRect)(nil), objc.ID(0), objc.ID(0))
	if nativeImage == 0 {
		return nil, errors.New("processinfo: native image has no CGImage")
	}
	// The snapshot is borrowed until the autorelease pool drains, not owned here.
	sourceWidth, sourceHeight := api.imageWidth(nativeImage), api.imageHeight(nativeImage)
	if sourceWidth > maxIconDimension || sourceHeight > maxIconDimension {
		return nil, errors.New("processinfo: native image dimensions exceed limit")
	}
	width, height, err := iconSize(int(sourceWidth), int(sourceHeight))
	if err != nil {
		return nil, err
	}
	length, err := nativeBufferSize(width, height, width*4)
	if err != nil {
		return nil, err
	}
	space := api.colorSpaceCreate()
	if space == 0 {
		return nil, errors.New("processinfo: create RGB color space")
	}
	defer api.colorSpaceFree(space)
	// Premultiplied-last plus 32-bit big-endian produces byte-ordered RGBA.
	context := api.contextCreate(nil, uintptr(width), uintptr(height), 8, uintptr(width*4), space, 1|4<<12)
	if context == 0 {
		return nil, errors.New("processinfo: create icon bitmap context")
	}
	defer api.contextFree(context)
	bounds := cgRect{size: cgSize{width: float64(width), height: float64(height)}}
	api.contextDraw(context, bounds, nativeImage)
	data := api.contextData(context)
	if data == nil {
		return nil, errors.New("processinfo: icon bitmap has no pixel data")
	}
	result := image.NewRGBA(image.Rect(0, 0, width, height))
	copy(result.Pix, unsafe.Slice((*byte)(data), length)) //nolint:gosec // Quartz owns this live buffer; its checked allocation is exactly stride times height.
	return result, nil
}
