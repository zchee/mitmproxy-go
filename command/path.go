// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package command

import (
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
)

// expandUser follows the host platform's Python os.path.expanduser, including
// its environment precedence and leaving unknown users unchanged.
func expandUser(s string) string {
	if !strings.HasPrefix(s, "~") {
		return s
	}
	seps := "/"
	if runtime.GOOS == "windows" {
		seps = `\/`
	}
	i := strings.IndexAny(s, seps)
	if i < 0 {
		i = len(s)
	}
	name := s[1:i]
	var home string
	if runtime.GOOS == "windows" {
		var ok bool
		home, ok = os.LookupEnv("USERPROFILE")
		if !ok {
			path, found := os.LookupEnv("HOMEPATH")
			if !found {
				return s
			}
			home = pyPathJoin(os.Getenv("HOMEDRIVE"), path)
		}
		if name != "" && name != os.Getenv("USERNAME") {
			base := home[strings.LastIndexAny(home, seps)+1:]
			if os.Getenv("USERNAME") != base {
				return s
			}
			home = pyPathJoin(pyDirname(home), name)
		}
		return home + s[i:]
	}
	var ok bool
	if name == "" {
		home, ok = os.LookupEnv("HOME")
	}
	if !ok {
		var account *user.User
		var err error
		if name == "" {
			account, err = user.LookupId(strconv.Itoa(os.Getuid()))
		} else {
			account, err = user.Lookup(name)
		}
		if err != nil {
			return s
		}
		home = account.HomeDir
	}
	result := strings.TrimRight(home, "/") + s[i:]
	if result == "" {
		return "/"
	}
	return result
}

func pathCompletion(start string) []string {
	if start == "" {
		start = "./"
	}
	path := expandUser(start)
	var files []string
	var prefix string
	if st, err := os.Stat(path); err == nil && st.IsDir() {
		files = pathGlob(pyPathJoin(path, "*"))
		prefix = start
	} else {
		files = pathGlob(path + "*")
		prefix = pyDirname(start)
	}
	if prefix == "" {
		prefix = "./"
	}
	ret := make([]string, 0, len(files))
	for _, f := range files {
		display := pyPathJoin(prefix, filepath.Base(f))
		if st, err := os.Stat(f); err == nil && st.IsDir() {
			display += "/"
		}
		ret = append(ret, display)
	}
	if len(ret) == 0 {
		return []string{start}
	}
	slices.Sort(ret)
	return ret
}

// pyPathJoin preserves spelling, unlike filepath.Join's cleaning. Its callers
// append single names, except for Windows HOMEDRIVE/HOMEPATH expansion.
func pyPathJoin(base, name string) string {
	if runtime.GOOS == "windows" {
		if filepath.VolumeName(name) != "" {
			return name
		}
		if strings.HasPrefix(name, `/`) || strings.HasPrefix(name, `\`) {
			return filepath.VolumeName(base) + name
		}
		if len(base) == 2 && base[1] == ':' {
			return base + name
		}
	} else if strings.HasPrefix(name, "/") {
		return name
	}
	if base == "" || os.IsPathSeparator(base[len(base)-1]) {
		return base + name
	}
	return base + string(os.PathSeparator) + name
}

func pyDirname(p string) string {
	seps := "/"
	volume, root := "", ""
	if runtime.GOOS == "windows" {
		seps = `\/`
		volume = filepath.VolumeName(p)
		p = p[len(volume):]
		if len(p) > 0 && os.IsPathSeparator(p[0]) {
			root, p = p[:1], p[1:]
		}
	}
	head := p[:strings.LastIndexAny(p, seps)+1]
	if runtime.GOOS == "windows" || strings.Trim(head, seps) != "" {
		head = strings.TrimRight(head, seps)
	}
	return volume + root + head
}

// pathGlob implements non-recursive Python glob semantics: no backslash
// escapes, hidden names only with a leading dot, and permissive bracket ranges.
func pathGlob(pattern string) []string {
	if !strings.ContainsAny(pattern, "*?[") {
		if _, err := os.Lstat(pattern); err == nil {
			return []string{pattern}
		}
		return nil
	}
	dir, base := filepath.Split(pattern)
	dirs := []string{dir}
	if dir != pattern && strings.ContainsAny(dir, "*?[") {
		dirs = pathGlob(pyDirname(pattern))
	}
	var results []string
	if runtime.GOOS == "windows" {
		base = strings.ToLower(base)
	}
	match, err := pathPattern(base)
	if err != nil {
		return nil
	}
	for _, dir := range dirs {
		path := dir
		if path == "" {
			path = "."
		}
		if base == "" {
			if st, err := os.Stat(path); err == nil && st.IsDir() {
				results = append(results, pyPathJoin(dir, ""))
			}
			continue
		}
		entries, err := os.ReadDir(path)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			name := entry.Name()
			if strings.HasPrefix(name, ".") && !strings.HasPrefix(base, ".") {
				continue
			}
			if runtime.GOOS == "windows" {
				name = strings.ToLower(name)
			}
			if match.MatchString(name) {
				results = append(results, pyPathJoin(dir, entry.Name()))
			}
		}
	}
	return results
}

func pathPattern(pattern string) (*regexp.Regexp, error) {
	chars := []rune(pattern)
	var re strings.Builder
	re.WriteString(`(?s)\A`)
	for i := 0; i < len(chars); i++ {
		switch chars[i] {
		case '*':
			re.WriteString(`.*`)
			for i+1 < len(chars) && chars[i+1] == '*' {
				i++
			}
		case '?':
			re.WriteByte('.')
		case '[':
			end := i + 1
			if end < len(chars) && chars[end] == '!' {
				end++
			}
			if end < len(chars) && chars[end] == ']' {
				end++
			}
			for end < len(chars) && chars[end] != ']' {
				end++
			}
			if end == len(chars) {
				re.WriteString(`\[`)
				continue
			}
			items := chars[i+1 : end]
			i = end
			negative := len(items) > 0 && items[0] == '!'
			if negative {
				items = items[1:]
			}
			var class strings.Builder
			for j := 0; j < len(items); j++ {
				lo, hi := items[j], items[j]
				if j+2 < len(items) && items[j+1] == '-' {
					hi = items[j+2]
					j += 2
				}
				if lo > hi {
					continue
				}
				class.WriteString(`\x{`)
				class.WriteString(strconv.FormatInt(int64(lo), 16))
				class.WriteByte('}')
				if lo != hi {
					class.WriteString(`-\x{`)
					class.WriteString(strconv.FormatInt(int64(hi), 16))
					class.WriteByte('}')
				}
			}
			if class.Len() == 0 {
				if negative {
					re.WriteByte('.')
				} else {
					re.WriteString(`\b\B`)
				}
			} else {
				re.WriteByte('[')
				if negative {
					re.WriteByte('^')
				}
				re.WriteString(class.String())
				re.WriteByte(']')
			}
		default:
			re.WriteString(regexp.QuoteMeta(string(chars[i])))
		}
	}
	re.WriteString(`\z`)
	return regexp.Compile(re.String())
}
