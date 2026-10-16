# Native ABI preparation

Model: claude-gpt-6.1-sol-ultrafast[1m]

Status: reconciled against the final official-document digest `apple-abi-docs.md`, SHA-256 `e93f795ea8bbb55c04f171f2253939453cb066e5aca960266730771c63aeb606`. This remains a preparation design, not native runtime acceptance. The digest supplies the fetched official Apple declarations, ownership rules, thread rules and pinned purego ABI evidence; its source register is authoritative over preliminary URLs in this note.

Base `86e74ccf8b076b06041f8caba5349f23a2720b90`; Rust pin `51fe2b7c5aa8439c162abb665db61c6669d146d6`. The repository has purego v0.11.1 indirectly but **no existing tracked purego/objc call site** at that base. Existing wrapper precedent must not be assumed. The purego implementation was read at `github.com/ebitengine/purego@v0.11.1/objc/objc_runtime_darwin.go`: `objc.ID`/`SEL`/`Class` are uintptr; `objc.Send[T]` selects objc_msgSend_stret for >16-byte struct returns on amd64 and ordinary objc_msgSend otherwise. Integer/object return calls may use ID.Send. All scalar and struct arguments must have the actual ABI type, not an untyped Go int.

## Reconciliation with the official digest

- The provisional note left NSWorkspace background safety open. The digest confirms sharedWorkspace, iconForFile: and NSRunningApplication atomic property reads are thread-safe, but NSImage use remains serialized and thread-confined. Public NSAutoreleasePool alloc/init/drain is the selected API, not private runtime pool symbols.
- Geometry is more specific than the provisional size-based summary: CGSize/CGPoint return through two FP result slots on both architectures; CGRect uses objc_msgSend_stret on amd64 but four FP result slots with ordinary objc_msgSend on arm64. All geometry uses typed objc.Send or typed registered C functions; never integer ID.Send.
- An empty owned window array differs from NULL. NULL is an explicit visibility query error, not a successful empty list. The chosen on-screen/non-desktop option already filters windows; no additional layer-zero restriction is added that would exclude valid floating windows.
- The initial plan did not decode onscreen/layer keys. Should onscreen be inspected, it is CFBoolean (CFBooleanGetValue), whereas PID/layer are CFNumber. The chosen owner-only extraction validates CFDictionary and CFNumber types and does not reinterpret a Boolean.
- NSBitmapImageRep initWithCGImage may retain the image without materializing pixels, and bitmapData can allocate lazily. The direct layout-reading route is not used. A CoreGraphics-owned fitted RGBA bitmap is chosen; source dimensions are checked before explicit pixel allocation, but no claim is made to cap opaque AppKit internal decoding.
- Borrowed CGImage is valid through the current pool and is never released by the caller. Both pointer lifetime and exactly-once release rules are confirmed.
- Additional official reference read for icon lookup without a gopsutil dependency: https://developer.apple.com/tutorials/data/documentation/appkit/nsworkspace/runningapplications.json. The Objective-C property is `@property (copy, readonly) NSArray<NSRunningApplication *> *runningApplications;`; calls are thread-safe and atomic, with changes following the main run loop. Iterate this borrowed array to find an exact executableURL path, then use its NSRunningApplication icon. This lets the Darwin icon path build while gopsutil is still excluded.

## Shared ABI rules

Darwin 64-bit: CFIndex/NSInteger = signed pointer-sized (Go int64); CFTypeID/NSUInteger/size_t = unsigned pointer-sized (Go uint64 or uintptr); pid_t = int32; CGWindowID/CGWindowListOption/CGBitmapInfo = uint32; CGFloat = float64. CF Boolean = unsigned byte (uint8); Objective-C BOOL = architecture-specific bool encoding but 1-byte value on supported Darwin arm64/amd64. Use typed structs marked `structs.HostLayout` for CGPoint/CGSize/CGRect (respectively two/two/four float64 fields). No float is sent as an integer ID. Check nil before every message that must return an object.

Load AppKit, CoreFoundation and CoreGraphics from their absolute system framework paths with `purego.Dlopen(RTLD_NOW|RTLD_LOCAL)` once; resolve every required symbol and cache selectors/classes. Framework handles remain live for the process lifetime. Symbol resolution failure is a returned initialization error, not fabricated output. An immutable function table is published through sync.Once initialization.

For an AppKit operation: serialize access to shared NSWorkspace/image cache objects, `runtime.LockOSThread`, allocate/init an NSAutoreleasePool, do work, copy output to owned Go memory, drain pool, unlock thread. Serializing and locking do not magically satisfy a main-thread-only requirement; such a requirement in the official review blocks this design. No UI windows/event loop/application activation will be created.

## Implemented selector inventory

The earlier tables retain considered alternatives for review. The actual Darwin draft uses only the following Objective-C selectors (in addition to the C table below); there is no call to NSBitmapImageRep, TIFFRepresentation, NSImage.size or runningApplicationWithProcessIdentifier:

| Receiver and exact declaration | Go binding shape | Ownership |
|---|---|---|
| NSObject `+ (instancetype)alloc`, `- (instancetype)init` | ID.Send with object result | +1 pool; failed init consumes receiver |
| NSAutoreleasePool `- (void)drain` | typed `func(objc.ID, objc.SEL)` bound to objc_msgSend | Drain exactly once, before OS-thread unlock |
| NSWorkspace `+ (NSWorkspace *)sharedWorkspace` | ID.Send, no args | Borrowed singleton |
| NSWorkspace `- (NSArray<NSRunningApplication *> *)runningApplications` | ID.Send, no args | Borrowed snapshot array, pool-confined |
| NSArray `- (NSUInteger)count` | objc.Send[uint64] | Scalar |
| NSArray `- (id)objectAtIndex:(NSUInteger)index` | ID.Send with uint64 index | Borrowed element; 0≤index<count |
| NSRunningApplication `- (NSURL *)executableURL` | ID.Send | Borrowed nullable URL |
| NSURL `- (NSString *)path` | ID.Send | Borrowed nullable string |
| NSString `- (const char *)UTF8String` | objc.Send[string] | purego copies the borrowed C string immediately |
| NSString `+ (instancetype)stringWithUTF8String:(const char *)value` | ID.Send with Go string converted to synchronous C string | Convenience +0 result copies input; reject invalid UTF-8/NUL first |
| NSRunningApplication `- (NSImage *)icon` | ID.Send | Borrowed nullable image |
| NSWorkspace `- (NSImage *)iconForFile:(NSString *)path` | ID.Send with NSString ID | Borrowed image; only for existing nondirectory path |
| NSImage `- (CGImageRef)CGImageForProposedRect:(NSRect *)rect context:(NSGraphicsContext *)context hints:(NSDictionary *)hints` | objc.Send[uintptr] with typed nil *cgRect and two nil IDs | Borrowed CGImage; nil rect avoids imposing a square aspect ratio |
| Tests: NSData `+ (instancetype)dataWithBytes:(const void *)bytes length:(NSUInteger)length` | ID.Send with unsafe.Pointer and uint64 | Copies bytes; +0 NSData, pool-confined |
| Tests: NSImage `- (instancetype)initWithData:(NSData *)data` | alloc then ID.Send | +1 NSImage; one typed release inside pool |
| Tests: NSObject `- (void)release` | typed void objc_msgSend | Removes owned fixture image claim once |

The C inventory includes CFDictionaryGetValue (actual `func(uintptr,uintptr) uintptr`) rather than the considered GetValueIfPresent variant, and adds no other CF ownership calls. CGImageForProposedRect is called with a nil proposed rectangle; actual returned dimensions determine the fit. Quartz allocates only the fitted bitmap (≤4096 bytes), then the draft copies it into image.RGBA and uses the shared bounded PNG encoder. All C function bindings and selectors are established once. The test-only native-result override counts actual color-space/context releases and proves an oversized source is rejected before those explicit allocations.

## CoreGraphics window listing

| Native declaration | Planned Go function binding | Ownership / checks | Official reference |
|---|---|---|---|
| `CFArrayRef CGWindowListCopyWindowInfo(CGWindowListOption option, CGWindowID relativeToWindow)` | `func(uint32, uint32) uintptr` | Call options 1\|16 and window 0; returned +1 array released once. NULL is a query failure; nonnil empty array is valid. | https://developer.apple.com/documentation/coregraphics/cgwindowlistcopywindowinfo(_:_:) |
| `CFIndex CFArrayGetCount(CFArrayRef)` | `func(uintptr) int64` | Borrowed array; require count >=0; loop every index including last. | https://developer.apple.com/documentation/corefoundation/cfarraygetcount(_:) |
| `const void *CFArrayGetValueAtIndex(CFArrayRef, CFIndex)` | `func(uintptr, int64) uintptr` | Borrowed dictionary valid until array release; type-check before dictionary API. | https://developer.apple.com/documentation/corefoundation/cfarraygetvalueatindex(_:_:) |
| `CFTypeID CFGetTypeID(CFTypeRef)` | `func(uintptr) uint64` | No ownership; nonzero input only. | https://developer.apple.com/documentation/corefoundation/cfgettypeid(_:) |
| `CFTypeID CFDictionaryGetTypeID(void)` | `func() uint64` | Constant type ID. | https://developer.apple.com/documentation/corefoundation/cfdictionarygettypeid() |
| `CFStringRef CFStringCreateWithCString(CFAllocatorRef, const char *, CFStringEncoding)` | `func(uintptr, string, uint32) uintptr` | Create `kCGWindowOwnerPID` key using UTF-8 0x08000100; copies string; release once after use. Avoid unsafe dereference of exported variable storage. | https://developer.apple.com/documentation/corefoundation/cfstringcreatewithcstring(_:_:_:) |
| `Boolean CFDictionaryGetValueIfPresent(CFDictionaryRef, const void *, const void **)` | `func(uintptr, uintptr, *uintptr) uint8` | Output number is borrowed; no release; validate CFNumber type. | https://developer.apple.com/documentation/corefoundation/cfdictionarygetvalueifpresent(_:_:_:) |
| `CFTypeID CFNumberGetTypeID(void)` | `func() uint64` | Constant type ID. | https://developer.apple.com/documentation/corefoundation/cfnumbergettypeid() |
| `Boolean CFNumberGetValue(CFNumberRef, CFNumberType, void *)` | `func(uintptr, int64, *int32) uint8` | kCFNumberSInt32Type=3; require conversion success and positive PID. Synchronous write to local scalar; no retained pointer. | https://developer.apple.com/documentation/corefoundation/cfnumbergetvalue(_:_:_:) |
| `void CFRelease(CFTypeRef)` | `func(uintptr)` | Exactly once for each owned CF value; never for a Get result or nil. | https://developer.apple.com/documentation/corefoundation/cfrelease(_:) |

Installed `CGWindow.h:163-172` says NULL occurs when the caller is outside a Quartz GUI session or WindowServer is disabled. Treating such NULL as an empty list would conceal an actual overall query failure. The upstream loop at nix_list.rs:112 omits its last value; this port intentionally iterates all values.

## AppKit object calls

Each method is called through purego objc with receiver and cached selector. `alloc` returns +1; `init` returns the same or replacement owned object; on failure, init consumes its receiver under Cocoa convention, so do not double-release a failed init. Convenience results and properties are borrowed/autoreleased, kept only inside the pool.

| Objective-C declaration / selector | Typed call shape after receiver/selector | Ownership / use | Official reference |
|---|---|---|---|
| `+[NSObject alloc]`, `-[NSObject init]` | `objc.ID` return, no arguments | NSAutoreleasePool and NSString owned allocation/init. | https://developer.apple.com/documentation/objectivec/nsobject |
| `-[NSAutoreleasePool drain]` | void-equivalent message | Drains and releases pool once, on the creating thread. All borrowed objects are dead afterward. | https://developer.apple.com/documentation/foundation/nsautoreleasepool |
| `-[NSObject release]` | void-equivalent message | Release owned NSString/image copy before pool drain; never release convenience/property returns. | https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/MemoryMgmt/Articles/mmRules.html |
| `+[NSRunningApplication runningApplicationWithProcessIdentifier:(pid_t)pid]` | `objc.Send[objc.ID](..., int32(pid))` | Borrowed nullable app. Iterate current adapter rows matching exact executable; not all processes are AppKit apps. | https://developer.apple.com/documentation/appkit/nsrunningapplication/init(processidentifier:) |
| `-[NSRunningApplication icon]` | `objc.ID` return | Borrowed nullable NSImage. API itself is documented thread-safe in SDK NSRunningApplication.h:49-58. | https://developer.apple.com/documentation/appkit/nsrunningapplication/icon |
| `+[NSWorkspace sharedWorkspace]` | `objc.ID` return | Borrowed singleton; serialize access pending threading review. | https://developer.apple.com/documentation/appkit/nsworkspace/shared |
| `-[NSString initWithBytes:(const void *)bytes length:(NSUInteger)length encoding:(NSStringEncoding)encoding]` | `objc.Send[objc.ID](..., pointer, uint64(len), uint64(4))` | Owned UTF-8 path, native copies bytes; keep input alive through call. Reject embedded NUL/invalid UTF-8 before filesystem/native use. | https://developer.apple.com/documentation/foundation/nsstring/init(bytes:length:encoding:) |
| `-[NSWorkspace iconForFile:(NSString *)fullPath]` | `objc.Send[objc.ID](..., pathID)` | Borrowed NSImage; only after existence check, so nonexistent path does not become a generic placeholder success. | https://developer.apple.com/documentation/appkit/nsworkspace/icon(forfile:) |
| `-[NSImage CGImageForProposedRect:(NSRect *)rect context:(NSGraphicsContext *)ctx hints:(NSDictionary *)hints]` | `objc.Send[uintptr](..., *cgRect, objc.ID(0), objc.ID(0))` | Returned CF image is explicitly CF_RETURNS_NOT_RETAINED; valid through current pool, NEVER CGImageRelease. Proposed rect initially 32×32 but is only a hint; validate actual returned dimensions. | https://developer.apple.com/documentation/appkit/nsimage/cgimage(forproposedrect:context:hints:) |

Installed NSImage.h:200-218 explicitly states that CGImageForProposedRect may return any representation despite hints; lifetime is the current autorelease pool and caller must not release it. It may allocate/cache internally to render a representation. The port can bound its own bitmap allocation after inspecting returned dimensions; it cannot promise that AppKit allocates nothing internally before returning. The final design must state that boundary accurately.

## Native pixel conversion (proposed minimal route)

Use CoreGraphics-owned RGBA storage, not an NSBitmapImageRep with unspecified native layout. NSBitmapImageRep `initWithCGImage:`, `bitmapData`, `bytesPerRow`, `bitsPerPixel`, `samplesPerPixel`, `bitmapFormat` were examined in the SDK as an alternative: it creates a new representation with layout needing extra interpretation, so this route is not selected unless the specialist finds the proposed route invalid. No TIFF codec is introduced.

| C declaration | Go binding | Ownership / checks | Official reference |
|---|---|---|---|
| `size_t CGImageGetWidth(CGImageRef)`, `size_t CGImageGetHeight(CGImageRef)` | each `func(uintptr) uint64` | Borrowed image; reject 0, >4096 or width×height×4 >64 MiB before bitmap allocation. | https://developer.apple.com/documentation/coregraphics/cgimage/width ; https://developer.apple.com/documentation/coregraphics/cgimage/height |
| `CGColorSpaceRef CGColorSpaceCreateDeviceRGB(void)` | `func() uintptr` | Owned +1; release with CGColorSpaceRelease. | https://developer.apple.com/documentation/coregraphics/cgcolorspace/init(devicergb:) |
| `void CGColorSpaceRelease(CGColorSpaceRef)` | `func(uintptr)` | Once, after context creation/use. | https://developer.apple.com/documentation/coregraphics/cgcolorspacerelease(_:) |
| `CGContextRef CGBitmapContextCreate(void *data,size_t width,size_t height,size_t bitsPerComponent,size_t bytesPerRow,CGColorSpaceRef space,CGBitmapInfo bitmapInfo)` | `func(uintptr,uint64,uint64,uint64,uint64,uintptr,uint32) uintptr` | Pass data=0; native owns storage. RGBA8 premultiplied-last with 32-big byte order; allocation only after width/stride checks. NULL is error. | https://developer.apple.com/documentation/coregraphics/cgcontext/init(data:width:height:bitspercomponent:bytesperrow:space:bitmapinfo:) |
| `void CGContextDrawImage(CGContextRef,CGRect,CGImageRef)` | `func(uintptr,cgRect,uintptr)` | Draw into own bitmap; struct by-value ABI must be validated on arm64 and cross-compiled amd64. | https://developer.apple.com/documentation/coregraphics/cgcontext/draw(_:in:bytiling:) |
| `void *CGBitmapContextGetData(CGContextRef)` | `func(uintptr) unsafe.Pointer` | Borrowed pointer; nonnil, copy exactly checked stride×height before context release. No Go pointer retained by C. | https://developer.apple.com/documentation/coregraphics/cgcontext/data |
| `void CGContextRelease(CGContextRef)` | `func(uintptr)` | Once, after copying pixels; releases native allocation. | https://developer.apple.com/documentation/coregraphics/cgcontextrelease(_:) |

The native image is copied into Go `image.RGBA` with premultiplied alpha; portable resizing preserves aspect ratio and image/png emits ≤1 MiB. Orientation must be checked with an asymmetric colored-corner image in addition to a real-icon PNG. Color order/premultiplication are not established by a successful PNG decode alone.

## Windows compile-only call set

Use x/sys/windows lazy system DLL procedures and explicit uint32/int32/uintptr ABI widths, no new dependency. Call set: OpenProcess/CloseHandle, QueryFullProcessImageNameW, IsProcessCritical; EnumWindows callback (HWND, LPARAM → BOOL), GetWindowThreadProcessId, IsWindowVisible, IsIconic, DwmGetWindowAttribute with 4-byte cloaked output; GetFileVersionInfoSizeW/GetFileVersionInfoW/VerQueryValueW for a visible group's FileDescription; GetModuleHandleW, ExtractAssociatedIconW, DestroyIcon, GetIconInfo, GetObjectW, GetDC/ReleaseDC, GetDIBits, DeleteObject. Process HANDLEs, HICON, both icon BITMAPs and HDC each have their own paired release, with defers installed immediately after successful acquisition. Bitmap structures have explicit C-width fields; BITMAPINFOHEADER is 40 bytes. Checked dimensions/stride precede GetDIBits destination allocation. A zero/missing color bitmap (monochrome icon) needs explicit handling/error, never dereference. Require a full returned scanline count, convert top-down BGRA to owned RGBA, then the portable32 sizing helper.

ExtractAssociatedIconW may alter its UTF-16 buffer, requires existing path validation, and must not receive the upstream truncated128-word array. Use the documented MAX_PATH buffer and explicit too-long-path error unless the official API guarantees extended paths. QueryFullProcessImageNameW uses an independently bounded growing buffer and fallback, resetting length each attempt. Windows source compiles/vets but native success, DWM filtering and handle behavior remain unverified until the Windows-host follow-up.

## Implementation review checks

- Confirm official-threading allowance for sharedWorkspace/iconForFile and CGImageForProposedRect outside the main thread; NSRunningApplication alone being thread-safe is insufficient.
- Confirm purego CGRect by-value float argument ABI for CGContextDrawImage and *CGRect argument for NSImage; do not emulate by sending raw integer words.
- Confirm window dictionary type/PID validation and zero-count handling.
- Confirm NSImage's borrowed CGImage lifetime and drain/release order; never call CGImageRelease on it.
- Confirm RGBA bitmap alpha/byte order and vertical orientation with deterministic pixels, not visual intuition.
- Clarify the AppKit-internal allocation boundary rather than claiming an unprovable pre-allocation bound for its opaque renderer.

## Windows references actually read for the draft

The following official pages were fetched before the Windows implementation draft:

- https://learn.microsoft.com/en-us/windows/win32/api/shellapi/nf-shellapi-extractassociatediconw — `HICON ExtractAssociatedIconW(HINSTANCE, LPWSTR, WORD *)`; mutable full-path buffer, NULL failure, caller must DestroyIcon. The page does not state a numeric buffer capacity: the draft deliberately rejects paths longer than MAX_PATH and supplies a MAX_PATH buffer rather than assuming unbounded support.
- https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-geticoninfo — `BOOL GetIconInfo(HICON, PICONINFO)`; both returned bitmap handles are owned and must be deleted with DeleteObject.
- https://learn.microsoft.com/en-us/windows/win32/api/wingdi/nf-wingdi-getdibits — `int GetDIBits(HDC,HBITMAP,UINT,UINT,LPVOID,LPBITMAPINFO,UINT)`; require copied scanline count, DWORD-aligned rows, negative height for top-down output, and bitmap must not be selected into a DC. The draft never selects either source bitmap into a DC.
- Context7 `/golang/sys` documentation and locally installed v0.49.0 `windows/syscall_windows.go`/`zsyscall_windows.go`/`dll_windows.go`: NewCallback uses stdcall with uintptr-sized values; Proc.Call errors are always nonnil and return status must be inspected first; syscall pointer liveness follows uintptr-escape rules. The draft allocates one permanent EnumWindows callback rather than leaking a callback slot each call.

Windows source remains compile-only. Portable pixel tests cover BGRA order, premultiplied alpha preservation, legacy AND-mask transparency, monochrome black/white/transparent pixels, malformed lengths and explicit rejection of destination-inverting monochrome icons (no fixed PNG can represent inversion). This last case is a named representability boundary, not a fabricated transparent result.
