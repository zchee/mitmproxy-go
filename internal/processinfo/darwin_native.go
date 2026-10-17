// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build darwin

package processinfo

import (
	"errors"
	"fmt"
	"sync"

	"github.com/ebitengine/purego"
)

type darwinNative struct {
	handles          []uintptr
	windowList       func(uint32, uint32) uintptr
	arrayCount       func(uintptr) int64
	arrayValue       func(uintptr, int64) uintptr
	dictionaryValue  func(uintptr, uintptr) uintptr
	typeID           func(uintptr) uintptr
	dictionaryTypeID func() uintptr
	numberTypeID     func() uintptr
	numberValue      func(uintptr, int64, *int32) uint8
	stringCreate     func(uintptr, string, uint32) uintptr
	cfRelease        func(uintptr)
}

var darwinAPI = sync.OnceValues(loadDarwinNative)

func loadDarwinNative() (api *darwinNative, err error) {
	api = &darwinNative{}
	defer func() {
		if err != nil {
			for _, handle := range api.handles {
				err = errors.Join(err, purego.Dlclose(handle))
			}
		}
	}()
	for _, path := range []string{
		"/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation",
		"/System/Library/Frameworks/CoreGraphics.framework/CoreGraphics",
	} {
		handle, err := purego.Dlopen(path, purego.RTLD_NOW|purego.RTLD_LOCAL)
		if err != nil {
			return api, fmt.Errorf("processinfo: load native framework: %w", err)
		}
		api.handles = append(api.handles, handle)
	}
	coreFoundation, coreGraphics := api.handles[0], api.handles[1]
	bindings := []struct {
		handle uintptr
		name   string
		target any
	}{
		{coreGraphics, "CGWindowListCopyWindowInfo", &api.windowList},
		{coreFoundation, "CFArrayGetCount", &api.arrayCount},
		{coreFoundation, "CFArrayGetValueAtIndex", &api.arrayValue},
		{coreFoundation, "CFDictionaryGetValue", &api.dictionaryValue},
		{coreFoundation, "CFGetTypeID", &api.typeID},
		{coreFoundation, "CFDictionaryGetTypeID", &api.dictionaryTypeID},
		{coreFoundation, "CFNumberGetTypeID", &api.numberTypeID},
		{coreFoundation, "CFNumberGetValue", &api.numberValue},
		{coreFoundation, "CFStringCreateWithCString", &api.stringCreate},
		{coreFoundation, "CFRelease", &api.cfRelease},
	}
	for _, binding := range bindings {
		symbol, err := purego.Dlsym(binding.handle, binding.name)
		if err != nil {
			return api, fmt.Errorf("processinfo: resolve %s: %w", binding.name, err)
		}
		purego.RegisterFunc(binding.target, symbol)
	}
	return api, nil
}

func visibleProcessIDs() (map[int32]struct{}, error) {
	api, err := darwinAPI()
	if err != nil {
		return nil, err
	}
	windows := api.windowList(1|16, 0)
	if windows == 0 {
		return nil, errors.New("processinfo: window list unavailable outside a GUI session")
	}
	defer api.cfRelease(windows)
	key := api.stringCreate(0, "kCGWindowOwnerPID", 0x08000100)
	if key == 0 {
		return nil, errors.New("processinfo: create window owner key")
	}
	defer api.cfRelease(key)
	return readWindowPIDs(api.arrayCount(windows), func(index int64) (int32, error) {
		dictionary := api.arrayValue(windows, index)
		if dictionary == 0 || api.typeID(dictionary) != api.dictionaryTypeID() {
			return 0, errors.New("processinfo: invalid window dictionary")
		}
		number := api.dictionaryValue(dictionary, key)
		if number == 0 || api.typeID(number) != api.numberTypeID() {
			return 0, errors.New("processinfo: invalid window owner")
		}
		var pid int32
		if api.numberValue(number, 3, &pid) == 0 {
			return 0, errors.New("processinfo: window owner is not an integer PID")
		}
		return pid, nil
	})
}
