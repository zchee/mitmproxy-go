// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package grideditor edits detached rows and commits validated changes through dispatch.
// The caller runs Model.Commit before popping an editor. A nil result permits a
// fresh pop dispatch; a contract.ErrorMsg leaves the editor open for correction.
package grideditor

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/httpmsg"
	"github.com/zchee/mitmproxy-go/internal/tools/console/external"
	"github.com/zchee/mitmproxy-go/internal/tools/console/internal/contract"
)

// Column describes a byte, text or attribute-subgrid column.
type Column struct {
	Name                      string
	Binary, Subgrid, ReadOnly bool
}

// Cell owns bytes or the rows of a nested attribute editor.
type Cell struct {
	Data     []byte
	Children [][]Cell
}

// CloneRows copies rows, byte values and nested attribute rows.
func CloneRows(rows [][]Cell) [][]Cell {
	if rows == nil {
		return nil
	}
	result := make([][]Cell, len(rows))
	for i, row := range rows {
		result[i] = make([]Cell, len(row))
		for j, cell := range row {
			result[i][j] = Cell{Data: bytes.Clone(cell.Data), Children: CloneRows(cell.Children)}
		}
	}
	return result
}

// Rows builds lossless working rows for a captured edit session.
func Rows(s *external.EditSession) ([]Column, [][]Cell, error) {
	pair := []Column{{Name: "Key"}, {Name: "Value"}}
	var rows [][]Cell
	add := func(a, b []byte) { rows = append(rows, []Cell{{Data: bytes.Clone(a)}, {Data: bytes.Clone(b)}}) }
	if s.Target.Part == "comment" {
		return []Column{{Name: "Value"}}, [][]Cell{{{Data: []byte(s.Flow.Common().Comment)}}}, nil
	}
	h, ok := s.Flow.(*flow.HTTPFlow)
	if !ok {
		data, err := s.Bytes()
		return []Column{{Name: "Value", Binary: true}}, [][]Cell{{{Data: data}}}, err
	}
	switch s.Target.Part {
	case "request-headers", "response-headers":
		headers := httpmsg.Headers(nil)
		if s.Target.Part == "request-headers" {
			if h.Request == nil {
				return nil, nil, errors.New("request missing")
			}
			headers = h.Request.Headers
		} else if h.Response != nil {
			headers = h.Response.Headers
		}
		for _, field := range headers {
			add(field.Name, field.Value)
		}
		pair[0].Binary, pair[1].Binary = true, true
	case "query", "urlencoded form":
		if h.Request == nil {
			return nil, nil, errors.New("request missing")
		}
		values := h.Request.Query()
		if s.Target.Part == "urlencoded form" {
			values = h.Request.URLEncodedForm()
		}
		for _, value := range values {
			add([]byte(value[0]), []byte(value[1]))
		}
	case "multipart form":
		if h.Request == nil {
			return nil, nil, errors.New("request missing")
		}
		for _, value := range h.Request.MultipartForm() {
			add(value[0], value[1])
		}
		pair[0].Binary, pair[1].Binary = true, true
	case "cookies":
		if h.Request == nil {
			return nil, nil, errors.New("request missing")
		}
		for _, cookie := range h.Request.Cookies() {
			add([]byte(cookie.Name), []byte(cookie.Value))
		}
	case "set-cookies":
		pair = append(pair, Column{Name: "Attributes", Subgrid: true})
		if h.Response != nil {
			for _, cookie := range h.Response.Cookies() {
				var cookieValue []byte
				if cookie.Value != nil {
					cookieValue = []byte(*cookie.Value)
				}
				row := []Cell{{Data: []byte(cookie.Name)}, {Data: cookieValue}, {}}
				for _, attr := range cookie.Attrs {
					var value []byte
					if attr.Value != nil {
						value = []byte(*attr.Value)
					}
					row[2].Children = append(row[2].Children, []Cell{{Data: []byte(attr.Name)}, {Data: value}})
				}
				rows = append(rows, row)
			}
		}
	case "path":
		if h.Request == nil {
			return nil, nil, errors.New("request missing")
		}
		pair = []Column{{Name: "Component"}}
		for _, component := range h.Request.PathComponents() {
			rows = append(rows, []Cell{{Data: []byte(component)}})
		}
	default:
		data, err := s.Bytes()
		return []Column{{Name: "Value", Binary: true}}, [][]Cell{{{Data: data}}}, err
	}
	return pair, rows, nil
}

// PrepareRows validates all rows on a detached copy before producing a commit.
// Empty rows are omitted as in the upstream grid's commit-on-pop behavior.
func PrepareRows(s *external.EditSession, rows [][]Cell) (contract.Edit, error) {
	columns, _, err := Rows(s)
	if err != nil {
		return contract.Edit{}, err
	}
	clean := make([][]Cell, 0, len(rows))
	for _, row := range rows {
		if len(row) != len(columns) {
			return contract.Edit{}, fmt.Errorf("row has %d cells, want %d", len(row), len(columns))
		}
		nonempty := false
		for _, cell := range row {
			nonempty = nonempty || len(cell.Data) > 0 || len(cell.Children) > 0
		}
		if nonempty {
			clean = append(clean, row)
		}
	}
	copySession := *s
	copySession.Flow = s.Flow.Copy()
	copySession.Flow.Common().ID = s.Target.FlowID
	if s.Target.Part == "comment" {
		copySession.Flow.Common().Comment = ""
		if len(clean) > 0 {
			copySession.Flow.Common().Comment = string(clean[0][0].Data)
		}
		return copySession.Prepared(), nil
	}
	h, ok := copySession.Flow.(*flow.HTTPFlow)
	if !ok {
		var data []byte
		if len(clean) > 0 {
			data = clean[0][0].Data
		}
		return copySession.PrepareBytes(data, false)
	}
	pairs := make([][2]string, 0, len(clean))
	binaryPairs := make([][2][]byte, 0, len(clean))
	if len(columns) >= 2 {
		for _, row := range clean {
			pairs = append(pairs, [2]string{string(row[0].Data), string(row[1].Data)})
			binaryPairs = append(binaryPairs, [2][]byte{bytes.Clone(row[0].Data), bytes.Clone(row[1].Data)})
		}
	}
	switch s.Target.Part {
	case "request-headers", "response-headers":
		headers := make(httpmsg.Headers, 0, len(clean))
		for _, row := range clean {
			headers = append(headers, httpmsg.Field{Name: bytes.Clone(row[0].Data), Value: bytes.Clone(row[1].Data)})
		}
		if s.Target.Part == "request-headers" {
			h.Request.Headers = headers
		} else {
			if h.Response == nil {
				h.Response, err = httpmsg.MakeResponse(200, []byte{}, nil)
				if err != nil {
					return contract.Edit{}, err
				}
			}
			h.Response.Headers = headers
		}
	case "query":
		h.Request.SetQuery(pairs)
	case "urlencoded form":
		h.Request.SetURLEncodedForm(pairs)
	case "multipart form":
		if err := h.Request.SetMultipartForm(binaryPairs); err != nil {
			return contract.Edit{}, err
		}
	case "cookies":
		cookies := make([]httpmsg.CookiePair, 0, len(pairs))
		for _, pair := range pairs {
			cookies = append(cookies, httpmsg.CookiePair{Name: pair[0], Value: pair[1]})
		}
		h.Request.SetCookies(cookies)
	case "set-cookies":
		cookies := make([]httpmsg.SetCookie, 0, len(clean))
		for _, row := range clean {
			cookie := httpmsg.SetCookie{Name: string(row[0].Data), Value: new(string(row[1].Data))}
			for _, attr := range row[2].Children {
				if len(attr) != 2 {
					return contract.Edit{}, errors.New("attribute needs two cells")
				}
				var value *string
				if len(attr[1].Data) > 0 {
					value = new(string(attr[1].Data))
				}
				cookie.Attrs = append(cookie.Attrs, httpmsg.CookieAttr{Name: string(attr[0].Data), Value: value})
			}
			cookies = append(cookies, cookie)
		}
		if h.Response == nil {
			h.Response, err = httpmsg.MakeResponse(200, []byte{}, nil)
			if err != nil {
				return contract.Edit{}, err
			}
		}
		h.Response.SetCookies(cookies)
	case "path":
		values := make([]string, 0, len(clean))
		for _, row := range clean {
			values = append(values, string(row[0].Data))
		}
		h.Request.SetPathComponents(values)
	default:
		var data []byte
		if len(clean) > 0 {
			data = clean[0][0].Data
		}
		return copySession.PrepareBytes(data, false)
	}
	return copySession.Prepared(), nil
}
