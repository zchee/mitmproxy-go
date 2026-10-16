// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build darwin

package processinfo

import (
	"errors"
	"fmt"
	"runtime"
	"structs"
	"sync"
	"unsafe"

	"github.com/ebitengine/purego"
	"github.com/ebitengine/purego/objc"
)

type cgPoint struct {
	_    structs.HostLayout
	x, y float64
}

type cgSize struct {
	_             structs.HostLayout
	width, height float64
}

type cgRect struct {
	_      structs.HostLayout
	origin cgPoint
	size   cgSize
}

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
	imageWidth       func(uintptr) uintptr
	imageHeight      func(uintptr) uintptr
	colorSpaceCreate func() uintptr
	colorSpaceFree   func(uintptr)
	contextCreate    func(unsafe.Pointer, uintptr, uintptr, uintptr, uintptr, uintptr, uint32) uintptr
	contextDraw      func(uintptr, cgRect, uintptr)
	contextData      func(uintptr) unsafe.Pointer
	contextFree      func(uintptr)
	sendVoid         func(objc.ID, objc.SEL)
	poolClass        objc.Class
	workspaceClass   objc.Class
	stringClass      objc.Class
	alloc            objc.SEL
	init             objc.SEL
	drain            objc.SEL
	sharedWorkspace  objc.SEL
	runningApps      objc.SEL
	count            objc.SEL
	objectAtIndex    objc.SEL
	executableURL    objc.SEL
	path             objc.SEL
	utf8String       objc.SEL
	stringWithUTF8   objc.SEL
	icon             objc.SEL
	iconForFile      objc.SEL
	cgImage          objc.SEL
}

var (
	darwinAPI = sync.OnceValues(loadDarwinNative)
	darwinMu  sync.Mutex
)

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
		"/System/Library/Frameworks/AppKit.framework/AppKit",
		"/usr/lib/libobjc.A.dylib",
	} {
		handle, err := purego.Dlopen(path, purego.RTLD_NOW|purego.RTLD_LOCAL)
		if err != nil {
			return api, fmt.Errorf("processinfo: load native framework: %w", err)
		}
		api.handles = append(api.handles, handle)
	}
	coreFoundation, coreGraphics, objectiveC := api.handles[0], api.handles[1], api.handles[3]
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
		{coreGraphics, "CGImageGetWidth", &api.imageWidth},
		{coreGraphics, "CGImageGetHeight", &api.imageHeight},
		{coreGraphics, "CGColorSpaceCreateDeviceRGB", &api.colorSpaceCreate},
		{coreGraphics, "CGColorSpaceRelease", &api.colorSpaceFree},
		{coreGraphics, "CGBitmapContextCreate", &api.contextCreate},
		{coreGraphics, "CGContextDrawImage", &api.contextDraw},
		{coreGraphics, "CGBitmapContextGetData", &api.contextData},
		{coreGraphics, "CGContextRelease", &api.contextFree},
		{objectiveC, "objc_msgSend", &api.sendVoid},
	}
	for _, binding := range bindings {
		symbol, err := purego.Dlsym(binding.handle, binding.name)
		if err != nil {
			return api, fmt.Errorf("processinfo: resolve %s: %w", binding.name, err)
		}
		purego.RegisterFunc(binding.target, symbol)
	}
	api.poolClass = objc.GetClass("NSAutoreleasePool")
	api.workspaceClass = objc.GetClass("NSWorkspace")
	api.stringClass = objc.GetClass("NSString")
	if api.poolClass == 0 || api.workspaceClass == 0 || api.stringClass == 0 {
		return api, errors.New("processinfo: required AppKit class unavailable")
	}
	api.alloc, api.init, api.drain = objc.RegisterName("alloc"), objc.RegisterName("init"), objc.RegisterName("drain")
	api.sharedWorkspace = objc.RegisterName("sharedWorkspace")
	api.runningApps = objc.RegisterName("runningApplications")
	api.count, api.objectAtIndex = objc.RegisterName("count"), objc.RegisterName("objectAtIndex:")
	api.executableURL, api.path = objc.RegisterName("executableURL"), objc.RegisterName("path")
	api.utf8String, api.stringWithUTF8 = objc.RegisterName("UTF8String"), objc.RegisterName("stringWithUTF8String:")
	api.icon, api.iconForFile = objc.RegisterName("icon"), objc.RegisterName("iconForFile:")
	api.cgImage = objc.RegisterName("CGImageForProposedRect:context:hints:")
	return api, nil
}

func withDarwinPool(operation func(*darwinNative) error) error {
	api, err := darwinAPI()
	if err != nil {
		return err
	}
	darwinMu.Lock()
	defer darwinMu.Unlock()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	pool := objc.ID(api.poolClass).Send(api.alloc)
	if pool != 0 {
		pool = pool.Send(api.init)
	}
	if pool == 0 {
		return errors.New("processinfo: create autorelease pool")
	}
	defer api.sendVoid(pool, api.drain)
	return operation(api)
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
