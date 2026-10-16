// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build windows

package processinfo

import (
	"errors"
	"fmt"
	"image"
	"os"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	shell32               = windows.NewLazySystemDLL("shell32.dll")
	gdi32                 = windows.NewLazySystemDLL("gdi32.dll")
	extractAssociatedIcon = shell32.NewProc("ExtractAssociatedIconW")
	destroyIcon           = user32.NewProc("DestroyIcon")
	getIconInfo           = user32.NewProc("GetIconInfo")
	getDC                 = user32.NewProc("GetDC")
	releaseDC             = user32.NewProc("ReleaseDC")
	getObject             = gdi32.NewProc("GetObjectW")
	getDIBits             = gdi32.NewProc("GetDIBits")
	deleteObject          = gdi32.NewProc("DeleteObject")
	windowsIcons          = newIconCache(256, 16<<20)
)

type iconInfo struct {
	isIcon   uint32
	xHotspot uint32
	yHotspot uint32
	mask     windows.Handle
	color    windows.Handle
}

type bitmap struct {
	kind       int32
	width      int32
	height     int32
	widthBytes int32
	planes     uint16
	bitsPixel  uint16
	bits       unsafe.Pointer
}

type bitmapHeader struct {
	size          uint32
	width         int32
	height        int32
	planes        uint16
	bitCount      uint16
	compression   uint32
	sizeImage     uint32
	xPelsPerMeter int32
	yPelsPerMeter int32
	clrUsed       uint32
	clrImportant  uint32
}

// ExecutableIcon returns a caller-owned PNG fitting within 32 by 32 pixels.
func ExecutableIcon(path string) ([]byte, error) {
	return windowsIcons.get(path, windowsIcon)
}

func windowsIcon(path string) (data []byte, err error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("processinfo: executable: %w", err)
	}
	if info.IsDir() {
		return nil, errors.New("processinfo: executable path is a directory")
	}
	name, err := windows.UTF16FromString(path)
	if err != nil {
		return nil, err
	}
	if len(name) > windows.MAX_PATH {
		return nil, errors.New("processinfo: icon path exceeds native path capacity")
	}
	buffer := make([]uint16, windows.MAX_PATH)
	copy(buffer, name)
	for _, procedure := range []*windows.LazyProc{extractAssociatedIcon, destroyIcon, getIconInfo, getDC, releaseDC, getObject, getDIBits, deleteObject} {
		if err := procedure.Find(); err != nil {
			return nil, fmt.Errorf("processinfo: load %s: %w", procedure.Name, err)
		}
	}
	var module windows.Handle
	if err := windows.GetModuleHandleEx(windows.GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, nil, &module); err != nil {
		return nil, err
	}
	var index uint16
	icon, _, cause := extractAssociatedIcon.Call(uintptr(module), uintptr(unsafe.Pointer(&buffer[0])), uintptr(unsafe.Pointer(&index)))
	if icon == 0 {
		return nil, windowsCallError("ExtractAssociatedIconW", cause)
	}
	defer func() {
		if result, _, cause := destroyIcon.Call(icon); result == 0 {
			err = errors.Join(err, windowsCallError("DestroyIcon", cause))
		}
	}()
	var native iconInfo
	if result, _, cause := getIconInfo.Call(icon, uintptr(unsafe.Pointer(&native))); result == 0 {
		return nil, windowsCallError("GetIconInfo", cause)
	}
	defer func() {
		for _, handle := range []windows.Handle{native.mask, native.color} {
			if handle != 0 {
				if result, _, cause := deleteObject.Call(uintptr(handle)); result == 0 {
					err = errors.Join(err, windowsCallError("DeleteObject", cause))
				}
			}
		}
	}()
	dc, _, cause := getDC.Call(0)
	if dc == 0 {
		return nil, windowsCallError("GetDC", cause)
	}
	defer func() {
		if result, _, cause := releaseDC.Call(0, dc); result == 0 {
			err = errors.Join(err, windowsCallError("ReleaseDC", cause))
		}
	}()
	var pixels *image.RGBA
	if native.color == 0 {
		mask, width, height, err := windowsBitmap(dc, native.mask)
		if err != nil {
			return nil, err
		}
		pixels, err = monochromeIcon(mask, width, height)
		if err != nil {
			return nil, err
		}
	} else {
		color, width, height, err := windowsBitmap(dc, native.color)
		if err != nil {
			return nil, err
		}
		var mask []byte
		if native.mask != 0 {
			var maskWidth, maskHeight int
			mask, maskWidth, maskHeight, err = windowsBitmap(dc, native.mask)
			if err != nil {
				return nil, err
			}
			if width != maskWidth || height != maskHeight {
				return nil, errors.New("processinfo: icon color and mask dimensions differ")
			}
		}
		pixels, err = colorIcon(color, mask, width, height)
		if err != nil {
			return nil, err
		}
	}
	return iconPNG(pixels)
}

func windowsBitmap(dc uintptr, handle windows.Handle) ([]byte, int, int, error) {
	if handle == 0 {
		return nil, 0, 0, errors.New("processinfo: missing icon bitmap")
	}
	var bitmap bitmap
	if result, _, cause := getObject.Call(uintptr(handle), unsafe.Sizeof(bitmap), uintptr(unsafe.Pointer(&bitmap))); result != unsafe.Sizeof(bitmap) {
		return nil, 0, 0, windowsCallError("GetObjectW", cause)
	}
	width, height := int(bitmap.width), int(bitmap.height)
	if _, _, err := iconSize(width, height); err != nil {
		return nil, 0, 0, err
	}
	length, err := nativeBufferSize(width, height, width*4)
	if err != nil {
		return nil, 0, 0, err
	}
	data := make([]byte, length)
	header := bitmapHeader{size: 40, width: bitmap.width, height: -bitmap.height, planes: 1, bitCount: 32}
	rows, _, cause := getDIBits.Call(dc, uintptr(handle), 0, uintptr(height), uintptr(unsafe.Pointer(&data[0])), uintptr(unsafe.Pointer(&header)), 0)
	runtime.KeepAlive(data)
	if rows != uintptr(height) {
		return nil, 0, 0, windowsCallError("GetDIBits", cause)
	}
	return data, width, height, nil
}
