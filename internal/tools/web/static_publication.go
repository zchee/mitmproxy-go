// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package web

import (
	"bytes"
	"context"
	"crypto/sha256"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"uuid"
)

const viewerMarker = ".mitmweb-owner.json"

type viewerOwner struct {
	Version     int    `json:"version"`
	UID         int    `json:"uid"`
	Destination string `json:"destination"`
	Stage       string `json:"stage"`
}

type viewerExport struct {
	parent, stage     *os.Root
	marker            *os.File
	name, destination string
	published         bool
}

func newViewerExport(destination string, files map[string][]byte) (_ *viewerExport, err error) {
	absolute, err := expandViewerPath(destination)
	if err != nil {
		return nil, err
	}
	if filepath.Base(absolute) == "." || filepath.Dir(absolute) == absolute {
		return nil, errors.New("static viewer destination must be an absent child directory")
	}
	parent, err := os.OpenRoot(filepath.Dir(absolute))
	if err != nil {
		return nil, err
	}
	export := &viewerExport{parent: parent, destination: filepath.Base(absolute)}
	defer func() {
		if err != nil {
			err = errors.Join(err, export.close())
		}
	}()
	if info, statErr := parent.Lstat(export.destination); statErr == nil {
		// Inspect an existing destination without following a symlink, but never
		// replace it, even if it is a complete previous export.
		if info.IsDir() {
			if existing, openErr := parent.OpenRoot(export.destination); openErr == nil {
				valid := validateViewerFiles(existing, files, "")
				closeErr := existing.Close()
				if valid == nil && closeErr == nil {
					return nil, fmt.Errorf("complete static viewer destination already exists: %w", fs.ErrExist)
				}
			}
		}
		return nil, fmt.Errorf("static viewer destination already exists: %w", fs.ErrExist)
	} else if !errors.Is(statErr, fs.ErrNotExist) {
		return nil, statErr
	}
	prefix := fmt.Sprintf(".mitmweb-%x-", sha256.Sum256([]byte(absolute)))
	if err := recoverViewerStages(parent, prefix, absolute); err != nil {
		return nil, err
	}
	export.name = prefix + uuid.New().String()
	if err := parent.Mkdir(export.name, 0o700); err != nil {
		return nil, err
	}
	export.stage, err = parent.OpenRoot(export.name)
	if err != nil {
		return nil, err
	}
	export.marker, err = export.stage.OpenFile(viewerMarker, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	if err := lockViewerFile(export.marker); err != nil {
		return nil, err
	}
	body, err := json.Marshal(viewerOwner{Version: 1, UID: os.Getuid(), Destination: absolute, Stage: export.name})
	if err != nil {
		return nil, err
	}
	if len(body) > 4096 {
		return nil, errors.New("static viewer ownership marker exceeds 4096 bytes")
	}
	if _, err := export.marker.Write(body); err != nil {
		return nil, err
	}
	return export, nil
}

func parseViewerOwner(body []byte, expected viewerOwner) error {
	if len(body) > 4096 {
		return errors.New("static viewer ownership marker exceeds 4096 bytes")
	}
	var owner viewerOwner
	if err := json.Unmarshal(body, &owner, json.RejectUnknownMembers(true)); err != nil {
		return err
	}
	if owner != expected {
		return errors.New("static viewer stage ownership does not match")
	}
	return nil
}

func recoverViewerStages(parent *os.Root, prefix, destination string) error {
	entries, err := fs.ReadDir(parent.FS(), ".")
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), prefix) {
			continue
		}
		id, parseErr := uuid.Parse(strings.TrimPrefix(entry.Name(), prefix))
		if parseErr != nil || prefix+id.String() != entry.Name() {
			return errors.New("unrecognized static viewer staging name")
		}
		info, err := parent.Lstat(entry.Name())
		if err != nil {
			return err
		}
		if !info.IsDir() || info.Mode().Perm() != 0o700 || !viewerOwned(info) {
			return errors.New("unrecognized static viewer staging directory")
		}
		stage, err := parent.OpenRoot(entry.Name())
		if err != nil {
			return err
		}
		cleanup := &viewerExport{parent: parent, stage: stage, name: entry.Name()}
		// The parent belongs to our caller; this temporary owner only releases
		// its stage and marker handles.
		err = func() (err error) {
			defer func() {
				err = errors.Join(err, stage.Close())
				if cleanup.marker != nil {
					err = errors.Join(err, cleanup.marker.Close())
				}
			}()
			info, err := stage.Lstat(viewerMarker)
			if err != nil {
				return fmt.Errorf("unrecognized static viewer stage: %w", err)
			}
			if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() > 4096 || !viewerOwned(info) {
				return errors.New("invalid static viewer ownership marker")
			}
			cleanup.marker, err = stage.OpenFile(viewerMarker, os.O_RDWR, 0)
			if err != nil {
				return err
			}
			if err := lockViewerFile(cleanup.marker); err != nil {
				return fmt.Errorf("static viewer stage is active or cannot be locked: %w", err)
			}
			body, err := io.ReadAll(io.LimitReader(cleanup.marker, 4097))
			if err != nil {
				return err
			}
			if err := parseViewerOwner(body, viewerOwner{Version: 1, UID: os.Getuid(), Destination: destination, Stage: entry.Name()}); err != nil {
				return err
			}
			return cleanup.removeStage()
		}()
		if err != nil {
			return err
		}
	}
	return nil
}

func (e *viewerExport) publish(ctx context.Context, files map[string][]byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateViewerFiles(e.stage, files, viewerMarker); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := e.stage.Remove(viewerMarker); err != nil {
		return err
	}
	published, err := renameViewerDirectory(e.parent, e.name, e.destination)
	e.published = published
	if err != nil {
		return fmt.Errorf("publish static viewer without replacement: %w", err)
	}
	return nil
}

func validateViewerFiles(root *os.Root, files map[string][]byte, marker string) error {
	directories := map[string]bool{".": true}
	for name := range files {
		for parent := path.Dir(name); parent != "."; parent = path.Dir(parent) {
			directories[parent] = true
		}
	}
	seen := 0
	err := fs.WalkDir(root.FS(), ".", func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if !directories[name] {
				return errors.New("unexpected static viewer directory")
			}
			return nil
		}
		if name == marker && marker != "" {
			return nil
		}
		body, ok := files[name]
		if !ok || !entry.Type().IsRegular() {
			return errors.New("unexpected static viewer file or symlink")
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Size() != int64(len(body)) {
			return errors.New("static viewer file size mismatch")
		}
		file, err := root.Open(name)
		if err != nil {
			return err
		}
		actual, readErr := io.ReadAll(io.LimitReader(file, int64(len(body))+1))
		if err := errors.Join(readErr, file.Close()); err != nil {
			return err
		}
		if !bytes.Equal(body, actual) {
			return errors.New("static viewer file content mismatch")
		}
		seen++
		return nil
	})
	if err != nil {
		return err
	}
	if seen != len(files) {
		return errors.New("static viewer inventory is incomplete")
	}
	return nil
}

func (e *viewerExport) removeStage() error {
	if e.stage == nil {
		return nil
	}
	entries, err := fs.ReadDir(e.stage.FS(), ".")
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.Name() == viewerMarker {
			continue
		}
		if err := e.stage.RemoveAll(entry.Name()); err != nil {
			return err
		}
	}
	if err := e.stage.Remove(viewerMarker); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	// Remove content through the anchored stage, never recursively through its
	// parent name: a renamed/replaced sibling must not have its contents deleted.
	original, err := e.stage.Stat(".")
	if err != nil {
		return err
	}
	current, err := e.parent.Lstat(e.name)
	if err != nil {
		return err
	}
	if !os.SameFile(original, current) {
		return errors.New("static viewer stage identity changed")
	}
	return e.parent.Remove(e.name)
}

func (e *viewerExport) close() error {
	var err error
	if !e.published {
		err = e.removeStage()
	}
	if e.marker != nil {
		err = errors.Join(err, e.marker.Close())
		e.marker = nil
	}
	if e.stage != nil {
		err = errors.Join(err, e.stage.Close())
		e.stage = nil
	}
	if e.parent != nil {
		err = errors.Join(err, e.parent.Close())
		e.parent = nil
	}
	return err
}
