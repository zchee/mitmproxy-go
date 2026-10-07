// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package privfile

import (
	"errors"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

func openPrivate(path string, appendMode bool) (_ *os.File, err error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, &os.PathError{Op: "identify private output owner", Path: path, Err: err}
	}
	descriptor, err := windows.SecurityDescriptorFromString("O:" + user.User.Sid.String() + "D:P(A;;FA;;;" + user.User.Sid.String() + ")")
	if err != nil {
		return nil, &os.PathError{Op: "prepare private output ACL", Path: path, Err: err}
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, &os.PathError{Op: "open private output", Path: path, Err: err}
	}
	attributes := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: descriptor}
	access := uint32(windows.GENERIC_WRITE | windows.READ_CONTROL | windows.WRITE_DAC)
	if appendMode {
		access = windows.FILE_APPEND_DATA | windows.FILE_READ_ATTRIBUTES | windows.READ_CONTROL | windows.WRITE_DAC
	}
	// OPEN_ALWAYS preserves existing contents until handle and ACL validation finish.
	handle, err := windows.CreateFile(name, access, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, &attributes, windows.OPEN_ALWAYS, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open private output", Path: path, Err: err}
	}
	file := os.NewFile(uintptr(handle), path)
	defer func() {
		if err != nil {
			err = errors.Join(err, file.Close())
		}
	}()
	kind, err := windows.GetFileType(handle)
	if err != nil {
		return nil, &os.PathError{Op: "stat private output", Path: path, Err: err}
	}
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return nil, &os.PathError{Op: "stat private output", Path: path, Err: err}
	}
	if kind != windows.FILE_TYPE_DISK || info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 {
		return nil, &os.PathError{Op: "open private output", Path: path, Err: errors.New("not a regular file")}
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return nil, &os.PathError{Op: "open private output", Path: path, Err: errors.New("symlink or reparse point refused")}
	}
	actual, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return nil, &os.PathError{Op: "stat private output owner", Path: path, Err: err}
	}
	owner, _, err := actual.Owner()
	if err != nil {
		return nil, &os.PathError{Op: "stat private output owner", Path: path, Err: err}
	}
	if owner == nil || !owner.Equals(user.User.Sid) {
		return nil, &os.PathError{Op: "open private output", Path: path, Err: errors.New("file owner is not the current user")}
	}
	acl, _, err := descriptor.DACL()
	if err != nil {
		return nil, &os.PathError{Op: "prepare private output ACL", Path: path, Err: err}
	}
	if err := windows.SetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		return nil, &os.PathError{Op: "restrict private output ACL", Path: path, Err: err}
	}
	if !appendMode {
		if err := file.Truncate(0); err != nil {
			return nil, &os.PathError{Op: "truncate private output", Path: path, Err: err}
		}
	}
	return file, nil
}
