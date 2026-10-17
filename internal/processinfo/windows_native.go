// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build windows

package processinfo

import (
	"errors"
	"fmt"
	"runtime"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	user32             = windows.NewLazySystemDLL("user32.dll")
	kernel32           = windows.NewLazySystemDLL("kernel32.dll")
	dwmapi             = windows.NewLazySystemDLL("dwmapi.dll")
	enumWindows        = user32.NewProc("EnumWindows")
	windowProcessID    = user32.NewProc("GetWindowThreadProcessId")
	isWindowVisible    = user32.NewProc("IsWindowVisible")
	isIconic           = user32.NewProc("IsIconic")
	dwmWindowAttribute = dwmapi.NewProc("DwmGetWindowAttribute")
	isProcessCritical  = kernel32.NewProc("IsProcessCritical")
	windowEnumMu       sync.Mutex
	windowPIDs         map[int32]struct{}
	windowCallback     = windows.NewCallback(func(window, _ uintptr) uintptr {
		visible, _, _ := isWindowVisible.Call(window)
		iconic, _, _ := isIconic.Call(window)
		if visible == 0 || iconic != 0 {
			return 1
		}
		var pid uint32
		thread, _, _ := windowProcessID.Call(window, uintptr(unsafe.Pointer(&pid)))
		if thread == 0 || pid == 0 || pid > 1<<31-1 {
			return 1
		}
		var cloaked uint32
		status, _, _ := dwmWindowAttribute.Call(window, 14, uintptr(unsafe.Pointer(&cloaked)), unsafe.Sizeof(cloaked))
		if int32(status) >= 0 && cloaked != 0 {
			return 1
		}
		windowPIDs[int32(pid)] = struct{}{}
		return 1
	})
)

func visibleProcessIDs() (map[int32]struct{}, error) {
	for _, procedure := range []*windows.LazyProc{enumWindows, windowProcessID, isWindowVisible, isIconic, dwmWindowAttribute} {
		if err := procedure.Find(); err != nil {
			return nil, fmt.Errorf("processinfo: load %s: %w", procedure.Name, err)
		}
	}
	// A single permanent callback avoids exhausting Windows' callback slots.
	windowEnumMu.Lock()
	defer windowEnumMu.Unlock()
	windowPIDs = make(map[int32]struct{})
	defer func() { windowPIDs = nil }()
	result, _, err := enumWindows.Call(windowCallback, 0)
	if result == 0 {
		return nil, windowsCallError("EnumWindows", err)
	}
	return windowPIDs, nil
}

func windowsCallError(operation string, err error) error {
	if errors.Is(err, windows.ERROR_SUCCESS) {
		return fmt.Errorf("processinfo: %s failed", operation)
	}
	return fmt.Errorf("processinfo: %s: %w", operation, err)
}

func windowsProcessDetails(pid int32) (path string, critical bool, err error) {
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return "", false, err
	}
	defer func() { err = errors.Join(err, windows.CloseHandle(handle)) }()
	buffer := make([]uint16, 32768)
	for _, flags := range [...]uint32{0, 1} {
		size := uint32(len(buffer))
		err = windows.QueryFullProcessImageName(handle, flags, &buffer[0], &size)
		if err == nil {
			if size == 0 || size > uint32(len(buffer)) {
				return "", false, fmt.Errorf("processinfo: invalid process image length %d", size)
			}
			path = windows.UTF16ToString(buffer[:size])
			break
		}
	}
	if err != nil {
		return "", false, fmt.Errorf("processinfo: process image: %w", err)
	}
	if err := isProcessCritical.Find(); err != nil {
		return "", false, err
	}
	var value uint32
	result, _, cause := isProcessCritical.Call(uintptr(handle), uintptr(unsafe.Pointer(&value)))
	if result == 0 {
		return "", false, windowsCallError("IsProcessCritical", cause)
	}
	return path, value != 0, nil
}

func windowsDisplayName(path string) (string, error) {
	size, err := windows.GetFileVersionInfoSize(path, nil)
	if err != nil {
		return "", err
	}
	if size == 0 || size > 1<<20 {
		return "", fmt.Errorf("processinfo: version information size %d exceeds bounds", size)
	}
	data := make([]byte, size)
	if err := windows.GetFileVersionInfo(path, 0, size, unsafe.Pointer(&data[0])); err != nil {
		return "", err
	}
	var translation unsafe.Pointer
	var length uint32
	if err := windows.VerQueryValue(unsafe.Pointer(&data[0]), `\VarFileInfo\Translation`, unsafe.Pointer(&translation), &length); err != nil {
		return "", err
	}
	if length < 4 || !withinVersionBuffer(data, translation, uintptr(length)) {
		return "", errors.New("processinfo: invalid version translation")
	}
	languages := unsafe.Slice((*uint16)(translation), length/2)
	key := fmt.Sprintf(`\StringFileInfo\%04x%04x\FileDescription`, languages[0], languages[1])
	var description unsafe.Pointer
	if err := windows.VerQueryValue(unsafe.Pointer(&data[0]), key, unsafe.Pointer(&description), &length); err != nil {
		return "", err
	}
	if length < 1 || uint64(length)*2 > uint64(len(data)) || !withinVersionBuffer(data, description, uintptr(length)*2) {
		return "", errors.New("processinfo: invalid file description")
	}
	name := windows.UTF16ToString(unsafe.Slice((*uint16)(description), length))
	runtime.KeepAlive(data)
	if name == "" {
		return "", errors.New("processinfo: empty file description")
	}
	return name, nil
}

func withinVersionBuffer(data []byte, pointer unsafe.Pointer, length uintptr) bool {
	base := uintptr(unsafe.Pointer(&data[0]))
	address := uintptr(pointer)
	return address >= base && address-base <= uintptr(len(data)) && length <= uintptr(len(data))-(address-base)
}
