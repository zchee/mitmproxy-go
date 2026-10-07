// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package privfile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"

	gocmp "github.com/google/go-cmp/cmp"
	"golang.org/x/sys/windows"
)

func windowsOutputUser(t *testing.T) *windows.SID {
	t.Helper()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	return user.User.Sid
}

func writeBroadWindowsOutput(t *testing.T, path string, owner *windows.SID) {
	t.Helper()
	descriptor, err := windows.SecurityDescriptorFromString("O:" + owner.String() + "D:(A;;FA;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	attributes := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: descriptor}
	handle, err := windows.CreateFile(name, windows.GENERIC_WRITE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, &attributes, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatalf("create broad-ACL fixture: %v", err)
	}
	file := os.NewFile(uintptr(handle), path)
	if _, err := file.WriteString("prior"); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestWindowsPrivateOutputACL(t *testing.T) {
	tests := map[string]struct{ append, existing bool }{
		"success: new protected file":           {},
		"success: new protected append file":    {append: true},
		"success: inherited broad ACL narrowed": {existing: true},
		"success: append broad ACL narrowed":    {append: true, existing: true},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			user := windowsOutputUser(t)
			path := filepath.Join(t.TempDir(), "private-output")
			if test.existing {
				writeBroadWindowsOutput(t, path, user)
			}
			open := Create
			if test.append {
				open = Append
			}
			file, err := open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = file.Close() }()
			descriptor, err := windows.GetSecurityInfo(windows.Handle(file.Fd()), windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
			if err != nil {
				t.Fatal(err)
			}
			control, _, err := descriptor.Control()
			if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
				t.Fatalf("DACL before write is not protected: control=%v error=%v", control, err)
			}
			sddl := descriptor.String()
			for ace := range strings.SplitSeq(sddl, "(") {
				_, attributes, ok := strings.Cut(ace, ";")
				if !ok {
					continue
				}
				flags, _, _ := strings.Cut(attributes, ";")
				if strings.Contains(flags, "ID") {
					t.Fatalf("DACL before write contains an inherited ACE: %s", sddl)
				}
			}
			// AI is descriptor propagation bookkeeping, distinct from INHERITED_ACE;
			// PROTECTED prevents inherited ACEs from modifying this DACL.
			// https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-control
			// Normalize only the returned in-memory copy, never the file ACL.
			if err := descriptor.SetControl(windows.SE_DACL_AUTO_INHERITED, 0); err != nil {
				t.Fatal(err)
			}
			wantDescriptor, err := windows.SecurityDescriptorFromString("O:" + user.String() + "D:P(A;;FA;;;" + user.String() + ")")
			if err != nil {
				t.Fatal(err)
			}
			if diff := gocmp.Diff(wantDescriptor.String(), descriptor.String()); diff != "" {
				t.Fatalf("owner-only descriptor before write (-want +got):\n%s", diff)
			}
			if _, err := file.WriteString("new"); err != nil {
				t.Fatal(err)
			}
			if err := file.Close(); err != nil {
				t.Fatal(err)
			}
			content, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			want := "new"
			if test.append && test.existing {
				want = "priornew"
			}
			if diff := gocmp.Diff(want, string(content)); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}

func TestWindowsPrivateOutputForeignOwner(t *testing.T) {
	user := windowsOutputUser(t)
	groups, err := windows.GetCurrentProcessToken().GetTokenGroups()
	if err != nil {
		t.Fatal(err)
	}
	administrators, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		t.Fatal(err)
	}
	var foreign *windows.SID
	for _, group := range groups.AllGroups() {
		if group.Attributes&windows.SE_GROUP_OWNER != 0 && !group.Sid.Equals(user) {
			if foreign == nil {
				foreign = group.Sid
			}
			if group.Sid.Equals(administrators) {
				foreign = group.Sid
				break
			}
		}
	}
	if foreign == nil {
		t.Fatal("owner-mismatch regression requires a distinct owner-eligible token group")
	}
	path := filepath.Join(t.TempDir(), "foreign-output")
	writeBroadWindowsOutput(t, path, foreign)
	tests := map[string]struct {
		open func(string) (*os.File, error)
	}{
		"error: create foreign-owned output": {open: Create},
		"error: append foreign-owned output": {open: Append},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			file, err := test.open(path)
			if err == nil {
				_ = file.Close()
				t.Fatal("foreign-owned file accepted")
			}
			content, readErr := os.ReadFile(path)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if diff := gocmp.Diff("prior", string(content)); diff != "" {
				t.Fatalf("rejected file content changed (-want +got):\n%s", diff)
			}
		})
	}
}
