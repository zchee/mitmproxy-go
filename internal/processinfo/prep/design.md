# Process listing and icon preparation

Model: claude-gpt-6.1-sol-ultrafast[1m]

Status: preparation design and portable draft, not native acceptance evidence. Base: `86e74ccf8b076b06041f8caba5349f23a2720b90`. Upstream Rust: `51fe2b7c5aa8439c162abb665db61c6669d146d6`; Python: `3368a0a06ae6195aad817a1ece1aaeb6fe0353a1`. Both local checkout HEADs were checked. Lead ruling R52-14 permits draft writes at final `internal/processinfo` paths on the isolated prep branch; no PR or main landing before transfer. The official Apple ABI document review is finalized in `apple-abi-docs.md` (SHA-256 `e93f795ea8bbb55c04f171f2253939453cb066e5aca960266730771c63aeb606`), and `abi.md` records its corrections.

## Public contract

```go
type Process struct {
    Executable, DisplayName string
    IsVisible, IsSystem bool
}
func ActiveExecutables() ([]Process, error)
func ExecutableIcon(path string) ([]byte, error)
```

Use the bootstrap's gopsutil v4.26.9 enumeration adapter after its transfer. Never read process environment or command-line arguments. Return an independently allocated process slice and PNG byte slice. Whole-enumeration or visibility-query failure returns a wrapped error; vanished/inaccessible individual processes are ignored on Unix. Sort source rows by PID before grouping to make nonvisibility field selection deterministic, and sort output by exact executable path for reproducible callers. Paths remain exact identity keys; do not clean, resolve symlinks or change case in the grouping function. Tests may normalize `os.Executable` for comparison to the platform's enumeration result.

Group exact paths into one Process, retaining the lowest-PID row's display/system fields and OR-ing visibility across every instance. Windows visible groups attempt FileDescription even if the lowest-PID row was invisible. Missing FileDescription uses the executable basename, not an empty label. Selection of the first PID and stable result sorting adapt upstream's hash-map nondeterminism; they are not upstream guarantees.

Source: `src/processes/nix_list.rs:15-84`, `windows_list.rs:171-230`, `mod.rs:26-34`; binding `mitmproxy-rs/src/process_info.rs:12-85`.

## Platform behavior

| Platform | Listing | Visibility | System classification | Icons |
|---|---|---|---|---|
| macOS | gopsutil PID/executable adapter | All CoreGraphics on-screen, non-desktop owner PIDs; iterate index 0 through count-1, including single/final window | Component-prefix `/System/`, not `/Systematic`; basename display | Running application icon first; NSWorkspace file icon fallback for an existing executable; bounded native RGBA to portable PNG |
| Linux | Same adapter, plus per-process real UID | Always false; no X11/Wayland work | UID <1000; unreadable UID defaults false as upstream | Typed unsupported error |
| Windows | gopsutil PID adapter; QueryFullProcessImageNameW with Win32 then native name and reset buffer length | EnumWindows; IsWindowVisible, not IsIconic, not DWM cloaked | IsProcessCritical with limited-information process handle | ExtractAssociatedIconW, GetIconInfo, GetDIBits; same portable PNG normalization |
| Other OS | Explicit typed unsupported | Not queried | Not guessed | Typed unsupported |

A nil CoreGraphics result is failure; a nonnil zero-count array is valid headless output. Do not preserve Rust's `0..count-1` omission (`nix_list.rs:112`). Windows DWM per-window failure follows upstream's uncloaked interpretation while EnumWindows failure is reported. All Windows native evidence is deferred; compile/vet and portable tests do not establish Windows native behavior.

## Portable image bounds and normalization

The native adapter validates positive width/height, each at most 4096, and checked stride×height at most 64 MiB BEFORE making an unsafe slice or allocating pixels. Stride is at least width×4, and checked for overflow. Only validated native bytes are copied into Go-owned RGBA memory while their owning native objects remain live. Padded rows are handled explicitly.

A shared sizing helper calculates a maximum edge of 32, preserving aspect ratio and rounding the short edge to the nearest positive integer (minimum 1). A square always becomes exactly 32×32, including a smaller source. Landscape 64×32 becomes 32×16; portrait 16×64 becomes 8×32. Oversized and invalid sources fail rather than being passed to a native renderer. Use the existing `golang.org/x/image/draw` scaler if imported through the unchanged graph; no custom resampler, no TIFF dependency. Encode with image/png into a writer that refuses output over 1 MiB before appending. The output is either a complete PNG or an error, never a partial success.

The same normalization is mandatory for both platforms. Resizing Windows icons differs deliberately from `windows_icons.rs:133-176`, which emits native dimensions.

## Finite successful-result cache

An internal cache owns a mutex, LRU list, exact-path map and SHA-256 content map. Capacity: at most 256 path entries and 16 MiB of unique retained PNG payloads. Each path maps to a content digest; content entries hold immutable PNG bytes and a reference count. A cache hit moves the path to MRU and returns a clone. Evict LRU path entries until both limits hold; decrement a content reference on every path eviction, dropping bytes/accounting at zero references. The hash covers the complete canonical PNG produced by the same encoder, so identical images share bytes without relying on native pointer identity. Bound input before hashing.

Loading and all native calls occur outside the cache lock. Concurrent misses may compute duplicates; under the lock, the first successful publisher wins, later publishers reuse that entry. No unbounded per-path in-flight map or goroutine is needed. Failures never publish path/content records, allowing a later successful retry. Caller mutation never affects cache bytes. Cache success does not promise file-change refresh until eviction, matching the plan's stated finite-cache compatibility boundary.

## Ownership and concurrency

Native API initialization resolves framework handles, classes, selectors and symbols once and returns a persistent initialization error on failure. Missing optional feature support is not a package-init panic. Each AppKit operation locks its goroutine to an OS thread, creates an autorelease pool, uses per-call image/bitmap state, copies pixels before cleanup and drains the pool before unlocking. A short native-operation mutex serializes AppKit access if required by the official threading review; it is distinct from the cache mutex and never nests inside it. No Go-owned pointer is retained by a native object beyond the synchronous call. Any API documented as main-thread-only is a blocking design issue, not permission to assume a locked arbitrary thread is the main thread.

CoreFoundation Copy/Create return values get exactly one CFRelease; Get-returned dictionary/number values are borrowed until the owning array is released. Objective-C alloc/init results get exactly one release (or pool drain for the pool); autoreleased property/convenience results are borrowed until draining the pool. Preserve cleanup order on every failure branch. The ABI note enumerates individual calls and will be finalized only after the official-document review.

Windows closes every successfully opened process HANDLE, destroys HICON, deletes both GetIconInfo bitmaps, releases the matching screen DC, checks every syscall result and keeps UTF-16 buffers live through calls. ExtractAssociatedIconW mutates its path buffer: validate NUL-free input and documented capacity, use a full buffer rather than truncating to 128 words. Query image names use a bounded grow/retry loop and reset length before switching to the native-name fallback. Version-info allocations are bounded, with VerQueryValueW pointers range-checked against their owning buffer.

## Draft and verification sequence

1. Obtain exact official Apple ABI/ownership/threading review; freeze this design's call set in abi.md.
2. Draft at final paths on the isolated prep branch under lead ruling R52-14; keep `processes.go` free for the bootstrap adapter and reconcile its real API after transfer.
3. Draft portable grouping, sizing and bounded cache with substantive tests. Gopsutil-dependent files remain build-tagged ignore until bootstrap/transfer; such files are explicitly uncompiled and not acceptance proof.
4. Draft macOS calls and real native tests only after ABI review; add Windows source with compile-only label and Linux unsupported icons.
5. After transfer, adapt to the real bootstrap API; format, lint, default/Windows/FreeBSD build+vet and gopls; execute the exact plan's locked portable60, Darwin5, Linux5 and preservation campaigns. Scoped native review is lead-owned and required before a landable PR.

## Planned tests

- `TestProcessGrouping`: exact-path deduplication, visibility OR, order-independent lowest-PID nonvisibility selection, distinct lexical paths, caller-owned results, omitted empty/inaccessible rows.
- `TestProcessPlatformRules`: `/System/` component boundary and basename, UID 0/999/1000/unknown, unsupported icon classification; `icon_sizing` square/landscape/portrait/tiny/zero/negative/oversized and checked stride bounds.
- `TestProcessIconCache`: same/different digest, path and byte LRU pressure, shared-digest refcounts, clone isolation, retry after failure, concurrent fills, no lock held in loader, oversized output rejection.
- `TestActiveExecutables`: native macOS/Linux list includes current executable after normalization, no empty executable, one row per exact path; no skip on missing current executable.
- `TestExecutableIconDarwin`: real current binary NSWorkspace fallback, PNG decode, positive ≤32 bounds and square32 behavior using portable fixture, missing path errors, repeated native calls/cleanup stress and concurrent callers. No synthetic blank icon on native failure, no GUI or root requirements.

## Remaining decisions and honest limits

The portable grouping, sizing/PNG and cache code is drafted at final package paths. Compile-only Windows source and real Darwin icon/visibility source are drafted. The first real Darwin run passed the current-binary icon, asymmetric transparent pixel fixture, owned-resource cleanup/failure, concurrent native calls and live window-query tests. The initial portable run exposed an unexported-field go-cmp assertion configuration error, corrected by allowing the internal record type for the nonmutation assertion. The final Apple ABI digest has been reconciled; the eventual gopsutil adapter shape remains open. The draft imports the already pinned x/image/draw and purego; the sole module owner will promote them to direct. Windows native list/icon/DWM evidence is a required later follow-up when those hosted legs resume. The owned color-space/context counters prove matching releases for this explicit path, not absence of all opaque AppKit caches or leaks.
