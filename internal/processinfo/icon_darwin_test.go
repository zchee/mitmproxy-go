// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build darwin

package processinfo

import (
	"bytes"
	"errors"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"unsafe"

	"github.com/ebitengine/purego/objc"
)

func TestExecutableIconDarwin(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]struct{ run func(*testing.T) }{
		"current_executable": {run: func(t *testing.T) {
			data, err := ExecutableIcon(executable)
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := png.Decode(bytes.NewReader(data))
			if err != nil {
				t.Fatal(err)
			}
			if decoded.Bounds().Size() != image.Pt(32, 32) || len(data) > maxPNGBytes {
				t.Fatalf("native icon has size %v, %d bytes", decoded.Bounds().Size(), len(data))
			}
		}},
		"invalid_path": {run: func(t *testing.T) {
			tests := map[string]struct{ path string }{
				"missing":      {path: filepath.Join(t.TempDir(), "missing")},
				"directory":    {path: t.TempDir()},
				"nul":          {path: "invalid\x00path"},
				"invalid_utf8": {path: "invalid\xffpath"},
			}
			for name, test := range tests {
				t.Run(name, func(t *testing.T) {
					if data, err := ExecutableIcon(test.path); err == nil || data != nil {
						t.Fatalf("invalid path returned %d bytes, %v", len(data), err)
					}
				})
			}
		}},
		"native_pixels": {run: func(t *testing.T) {
			err := withDarwinPool(func(api *darwinNative) error {
				source, err := darwinFixture(api)
				if err != nil {
					return err
				}
				defer api.sendVoid(source, objc.RegisterName("release"))
				pixels, err := renderDarwinImage(api, source)
				if err != nil {
					return err
				}
				if pixels.Bounds().Size() != image.Pt(32, 16) {
					return fmt.Errorf("native landscape size = %v, want (32,16)", pixels.Bounds().Size())
				}
				tests := map[string]struct {
					point image.Point
					want  color.NRGBA
				}{
					"top_left":     {point: image.Pt(2, 2), want: color.NRGBA{R: 255, A: 128}},
					"top_right":    {point: image.Pt(29, 2), want: color.NRGBA{G: 255, A: 255}},
					"bottom_left":  {point: image.Pt(2, 13), want: color.NRGBA{B: 255, A: 255}},
					"bottom_right": {point: image.Pt(29, 13), want: color.NRGBA{}},
				}
				for name, test := range tests {
					got := color.NRGBAModel.Convert(pixels.At(test.point.X, test.point.Y)).(color.NRGBA)
					if got != test.want {
						return fmt.Errorf("%s native pixel = %#v, want %#v", name, got, test.want)
					}
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
		}},
		"native_ownership": {run: func(t *testing.T) {
			err := withDarwinPool(func(api *darwinNative) error {
				source, err := darwinFixture(api)
				if err != nil {
					return err
				}
				defer api.sendVoid(source, objc.RegisterName("release"))
				calls := *api
				var freedSpaces, freedContexts int
				calls.colorSpaceFree = func(space uintptr) { freedSpaces++; api.colorSpaceFree(space) }
				calls.contextFree = func(context uintptr) { freedContexts++; api.contextFree(context) }
				if _, err := renderDarwinImage(&calls, source); err != nil {
					return err
				}
				if freedSpaces != 1 || freedContexts != 1 {
					return fmt.Errorf("success cleanup: spaces %d, contexts %d", freedSpaces, freedContexts)
				}
				calls.contextCreate = func(unsafe.Pointer, uintptr, uintptr, uintptr, uintptr, uintptr, uint32) uintptr { return 0 }
				if _, err := renderDarwinImage(&calls, source); err == nil {
					return errors.New("failed native allocation returned success")
				}
				if freedSpaces != 2 || freedContexts != 1 {
					return fmt.Errorf("failure cleanup: spaces %d, contexts %d", freedSpaces, freedContexts)
				}
				var allocations int
				calls.imageWidth = func(uintptr) uintptr { return maxIconDimension + 1 }
				calls.colorSpaceCreate = func() uintptr { allocations++; return api.colorSpaceCreate() }
				if _, err := renderDarwinImage(&calls, source); err == nil || allocations != 0 {
					return fmt.Errorf("oversized image: error %v, native allocations %d", err, allocations)
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
		}},
		"concurrent_native_calls": {run: func(t *testing.T) {
			var workers sync.WaitGroup
			for range 8 {
				workers.Go(func() {
					data, err := darwinIcon(executable)
					if err != nil || len(data) == 0 {
						t.Errorf("native concurrent call: %d bytes, %v", len(data), err)
					}
				})
			}
			workers.Wait()
		}},
		"window_query": {run: func(t *testing.T) {
			if _, err := visibleProcessIDs(); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for name, test := range tests {
		t.Run(name, test.run)
	}
}

func darwinFixture(api *darwinNative) (objc.ID, error) {
	pixels := image.NewNRGBA(image.Rect(0, 0, 64, 32))
	for y := range 32 {
		for x := range 64 {
			pixel := color.NRGBA{}
			switch {
			case x < 32 && y < 16:
				pixel = color.NRGBA{R: 255, A: 128}
			case x >= 32 && y < 16:
				pixel = color.NRGBA{G: 255, A: 255}
			case x < 32:
				pixel = color.NRGBA{B: 255, A: 255}
			}
			pixels.SetNRGBA(x, y, pixel)
		}
	}
	var encoded bytes.Buffer
	if err := png.Encode(&encoded, pixels); err != nil {
		return 0, err
	}
	data := encoded.Bytes()
	nativeData := objc.ID(objc.GetClass("NSData")).Send(objc.RegisterName("dataWithBytes:length:"), unsafe.Pointer(&data[0]), uint64(len(data)))
	runtime.KeepAlive(data)
	if nativeData == 0 {
		return 0, errors.New("create native fixture data")
	}
	source := objc.ID(objc.GetClass("NSImage")).Send(api.alloc)
	if source != 0 {
		source = source.Send(objc.RegisterName("initWithData:"), nativeData)
	}
	if source == 0 {
		return 0, errors.New("create native fixture image")
	}
	return source, nil
}
