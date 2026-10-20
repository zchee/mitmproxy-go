// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package web

import (
	"bytes"
	"context"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"path"
	"regexp"
	"strconv"
	"strings"

	"github.com/zchee/mitmproxy-go/addons/eventstore"
	"github.com/zchee/mitmproxy-go/addons/view"
	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/filter"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/flowio"
	"github.com/zchee/mitmproxy-go/flowio/flowjson"
	"github.com/zchee/mitmproxy-go/internal/processinfo"
	"github.com/zchee/mitmproxy-go/internal/version"
	"github.com/zchee/mitmproxy-go/master"
	"github.com/zchee/mitmproxy-go/options"
)

type application struct {
	master    *master.Master
	view      *view.View
	events    *eventstore.EventStore
	eventRows func() []map[string]any
	protect   func(http.Handler, bool) http.Handler
	firstFile func(*http.Request) (*multipart.FileHeader, bool)
}

type webRoute struct {
	name    string
	pattern *regexp.Regexp
	methods string
}

var webRoutes = []webRoute{
	{"index", regexp.MustCompile(`^/$`), "GET POST"},
	{"filter_help", regexp.MustCompile(`^/filter-help(?:\.json)?$`), "GET"},
	{"commands", regexp.MustCompile(`^/commands(?:\.json)?$`), "GET"},
	{"command_execute", regexp.MustCompile(`^/commands/([a-z.]+)$`), "POST"},
	{"events", regexp.MustCompile(`^/events(?:\.json)?$`), "GET"},
	{"flows", regexp.MustCompile(`^/flows(?:\.json)?$`), "GET"},
	{"flows_dump", regexp.MustCompile(`^/flows/dump$`), "GET POST"},
	{"flows_resume", regexp.MustCompile(`^/flows/resume$`), "POST"},
	{"flows_kill", regexp.MustCompile(`^/flows/kill$`), "POST"},
	{"flow", regexp.MustCompile(`^/flows/([0-9a-f\-]+)$`), "PUT DELETE"},
	{"flow_resume", regexp.MustCompile(`^/flows/([0-9a-f\-]+)/resume$`), "POST"},
	{"flow_kill", regexp.MustCompile(`^/flows/([0-9a-f\-]+)/kill$`), "POST"},
	{"flow_duplicate", regexp.MustCompile(`^/flows/([0-9a-f\-]+)/duplicate$`), "POST"},
	{"flow_replay", regexp.MustCompile(`^/flows/([0-9a-f\-]+)/replay$`), "POST"},
	{"flow_revert", regexp.MustCompile(`^/flows/([0-9a-f\-]+)/revert$`), "POST"},
	{"flow_content", regexp.MustCompile(`^/flows/([0-9a-f\-]+)/(request|response|messages)/content\.data$`), "GET POST"},
	{"flow_content_view", regexp.MustCompile(`^/flows/([0-9a-f\-]+)/(request|response|messages)/content/([0-9a-zA-Z\-_%]+)(?:\.json)?$`), "GET"},
	{"clear", regexp.MustCompile(`^/clear$`), "POST"},
	{"options", regexp.MustCompile(`^/options(?:\.json)?$`), "GET PUT"},
	{"options_save", regexp.MustCompile(`^/options/save$`), "POST"},
	{"processes", regexp.MustCompile(`^/processes$`), "GET"},
	{"executable_icon", regexp.MustCompile(`^/executable-icon$`), "GET"},
}

func (a *application) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if value := recover(); value != nil {
				writeWebError(w, r, fmt.Errorf("web handler panic (%T)", value))
			}
		}()
		for _, route := range webRoutes {
			if route.name == "events" && a.eventRows == nil { continue }
			captures := route.pattern.FindStringSubmatch(r.URL.Path)
			if captures == nil {
				continue
			}
			securityHeaders(w)
			// Tornado does not derive HEAD from GET, and unimplemented methods are not auth-wrapped.
			if !strings.Contains(" "+route.methods+" ", " "+r.Method+" ") {
				writeWebError(w, r, apiError(405, ""))
				return
			}
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if err := a.serve(w, r, route.name, captures[1:]); err != nil {
					writeWebError(w, r, err)
				}
			})
			if a.protect == nil {
				writeWebError(w, r, apiError(403, ""))
				return
			}
			a.protect(handler, route.name == "index").ServeHTTP(w, r)
			return
		}
		writeWebError(w, r, apiError(404, ""))
	})
	static := StaticHandler()
	return withGzip(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, receiveLimit)
		if strings.HasPrefix(r.URL.Path, "/static/") {
			static.ServeHTTP(w, r)
			return
		}
		// Reject noncanonical paths instead of ServeMux's automatic clean-path redirect.
		if path.Clean(r.URL.Path) != r.URL.Path {
			writeWebError(w, r, apiError(404, ""))
			return
		}
		mux.ServeHTTP(w, r)
	}))
}

func securityHeaders(w http.ResponseWriter) {
	w.Header().Set("Server", version.String())
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-XSS-Protection", "1; mode=block")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; connect-src 'self' ws:; img-src 'self' data:; style-src   'self' 'unsafe-inline'")
}

func writeJSON(w http.ResponseWriter, value any) error {
	body, err := json.Marshal(value, json.Deterministic(true), json.FormatNilSliceAsNull(false), json.FormatNilMapAsNull(false))
	if err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	_, err = w.Write(body)
	return err
}

func (a *application) serve(w http.ResponseWriter, r *http.Request, name string, args []string) error {
	switch name {
	case "index":
		IndexHandler().ServeHTTP(w, r)
		return nil
	case "filter_help":
		return writeJSON(w, map[string]any{"commands": filterHelp})
	case "options_save":
		// The upstream endpoint intentionally acknowledges without writing settings.
		return nil
	case "processes":
		processes, err := processinfo.ActiveExecutables()
		if err != nil {
			return err
		}
		values := make([]map[string]any, 0, len(processes))
		for _, p := range processes {
			values = append(values, map[string]any{"is_visible": p.IsVisible, "executable": p.Executable, "is_system": p.IsSystem, "display_name": p.DisplayName})
		}
		return writeJSON(w, values)
	case "executable_icon":
		values := r.URL.Query()["path"]
		if len(values) == 0 || strings.TrimSpace(values[len(values)-1]) == "" {
			return apiError(400, "Missing 'path' parameter.")
		}
		icon, err := processinfo.ExecutableIcon(strings.TrimSpace(values[len(values)-1]))
		if err != nil {
			icon = transparentPNG
		}
		w.Header().Set("Content-Type", "image/png")
		w.Header().Set("Cache-Control", "max-age=604800")
		_, err = w.Write(icon)
		return err
	case "flows_dump":
		return a.dumpFlows(w, r)
	case "flow_content", "flow_content_view":
		return a.flowContent(w, r, name, args)
	}
	var inputJSON []byte
	if name == "options" && r.Method == http.MethodPut || name == "flow" && r.Method == http.MethodPut || name == "command_execute" {
		var err error
		inputJSON, err = requestJSON(r)
		if err != nil && name != "command_execute" {
			if name == "flow" {
				return a.master.Do(r.Context(), func(context.Context) error {
					f := a.view.GetByID(args[0])
					if f == nil {
						return apiError(404, "Flow not found.")
					}
					f.Backup()
					if revertErr := f.Revert(); revertErr != nil {
						return errors.Join(err, revertErr)
					}
					return err
				})
			}
			return err
		}
	}
	var body []byte
	var response any
	var text string
	err := a.master.Do(r.Context(), func(ctx context.Context) error {
		switch name {
		case "flows":
			values := make([]jsontext.Value, 0, a.view.Len())
			for _, f := range a.view.Flows() {
				value, err := flowjson.Flow(f)
				if err != nil {
					return err
				}
				encoded, err := json.Marshal(value)
				if err != nil {
					return err
				}
				values = append(values, encoded)
			}
			response = values
		case "events":
			response = a.eventRows()
		case "commands":
			values := make(map[string]any)
			for commandName, cmd := range a.master.Commands.Commands() {
				parameters := make([]map[string]string, 0, len(cmd.Params))
				for _, p := range cmd.Params {
					kind := "POSITIONAL_OR_KEYWORD"
					if p.Variadic {
						kind = "VAR_POSITIONAL"
					}
					parameters = append(parameters, map[string]string{"name": p.Name, "type": p.Type.Display(), "kind": kind})
				}
				var returnType any
				if cmd.Return != nil {
					returnType = cmd.Return.Display()
				}
				values[commandName] = map[string]any{"help": cmd.Help, "parameters": parameters, "return_type": returnType, "signature_help": cmd.SignatureHelp()}
			}
			response = values
		case "command_execute":
			var arguments []string
			if len(inputJSON) > 0 {
				object, err := jsonObject(inputJSON)
				if err != nil {
					return err
				}
				raw, ok := object.Get("arguments")
				if !ok {
					return fmt.Errorf("missing command arguments")
				}
				if err := json.Unmarshal(raw, &arguments); err != nil {
					response = map[string]any{"error": err.Error()}
					break
				}
			}
			result, err := a.master.Commands.CallStrings(ctx, args[0], arguments)
			if err != nil {
				message := err.Error()
				if errors.Is(err, command.ErrUnknownCommand) {
					message = "Unknown command: " + args[0]
				}
				response = map[string]any{"error": message}
			} else {
				response = map[string]any{"value": result}
			}
		case "options":
			if r.Method == http.MethodGet {
				response = optionDictionary(a.master.Options)
				break
			}
			values, err := optionUpdate(inputJSON)
			if err != nil {
				return apiError(400, err.Error())
			}
			if err := a.master.Options.Update(ctx, values); err != nil {
				return apiError(400, err.Error())
			}
		case "clear":
			if _, err := a.master.Call(ctx, "view.clear"); err != nil {
				return err
			}
			_, err := a.master.Call(ctx, "eventstore.clear")
			return err
		case "flows_resume", "flows_kill":
			for _, f := range a.view.Flows() {
				if name == "flows_resume" && f.Common().Intercepted() {
					f.Common().Resume()
				} else if name == "flows_kill" && f.Common().Killable() {
					if err := f.Common().Kill(); err != nil {
						return err
					}
				} else {
					continue
				}
				if err := a.view.Update(ctx, []flow.Flow{f}); err != nil {
					return err
				}
			}
		default:
			f := a.view.GetByID(args[0])
			if f == nil {
				return apiError(404, "Flow not found.")
			}
			switch name {
			case "flow":
				if r.Method == http.MethodDelete {
					_, err := a.master.Call(ctx, "view.flows.remove", []flow.Flow{f})
					return err
				}
				return a.editFlow(ctx, f, inputJSON)
			case "flow_resume":
				f.Common().Resume()
				return a.view.Update(ctx, []flow.Flow{f})
			case "flow_kill":
				if f.Common().Killable() {
					if err := f.Common().Kill(); err != nil {
						return err
					}
					return a.view.Update(ctx, []flow.Flow{f})
				}
			case "flow_duplicate":
				duplicate := f.Copy()
				a.view.Add(ctx, []flow.Flow{duplicate})
				text = duplicate.Common().ID
			case "flow_replay":
				_, err := a.master.Call(ctx, "replay.client", []flow.Flow{f})
				return err
			case "flow_revert":
				if f.Modified() {
					if err := f.Revert(); err != nil {
						return err
					}
					return a.view.Update(ctx, []flow.Flow{f})
				}
			}
		}
		// Marshal every response before releasing dispatch: maps may contain command-owned state.
		if response != nil {
			var err error
			body, err = json.Marshal(response, json.Deterministic(true), json.FormatNilSliceAsNull(false))
			return err
		}
		body = nil
		return nil
	})
	if err != nil {
		return err
	}
	if text != "" {
		_, err = io.WriteString(w, text)
		return err
	}
	if body != nil {
		w.Header().Set("Content-Type", "application/json; charset=UTF-8")
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		_, err = w.Write(body)
	}
	return err
}

func optionDictionary(opts *options.Manager) map[string]any {
	result := make(map[string]any)
	for _, option := range opts.Items() {
		var choices any = jsontext.Value("null")
		if option.Choices() != nil {
			choices = option.Choices()
		}
		result[option.Name()] = map[string]any{"type": option.Type().String(), "default": option.Default(), "value": option.Current(), "help": option.Help(), "choices": choices}
	}
	return result
}

func optionUpdate(body []byte) (map[string]any, error) {
	object, err := jsonObject(body)
	if err != nil {
		return nil, err
	}
	values := make(map[string]any)
	for key, raw := range object.All() {
		var value any
		if len(raw) > 0 && (raw[0] == '-' || raw[0] >= '0' && raw[0] <= '9') {
			var number int
			if json.Unmarshal(raw, &number) == nil {
				value = number
			} else if err := json.Unmarshal(raw, &value); err != nil {
				return nil, err
			}
		} else if err := json.Unmarshal(raw, &value); err != nil {
			return nil, err
		}
		values[key] = value
	}
	return values, nil
}

func (a *application) upload(r *http.Request) (io.ReadCloser, error) {
	if a.firstFile != nil {
		if file, ok := a.firstFile(r); ok {
			return file.Open()
		}
	}
	return r.Body, nil
}

func (a *application) dumpFlows(w http.ResponseWriter, r *http.Request) error {
	if r.Method == http.MethodPost {
		if err := a.master.Do(r.Context(), func(ctx context.Context) error { _, err := a.master.Call(ctx, "view.clear"); return err }); err != nil {
			return err
		}
		input, err := a.upload(r)
		if err != nil {
			return err
		}
		defer func() { _ = input.Close() }()
		reader := flowio.NewReader(input)
		for {
			f, err := reader.Next()
			if err == io.EOF {
				return nil
			}
			if err != nil {
				return err
			}
			if err := a.master.LoadFlow(r.Context(), f); err != nil {
				return err
			}
		}
	}
	var expression filter.Expr
	if values, ok := r.URL.Query()["filter"]; ok && len(values) > 0 {
		var err error
		expression, err = filter.Parse(values[0])
		if err != nil {
			return apiError(400, "Invalid filter argument / regex")
		}
	}
	var body bytes.Buffer
	err := a.master.Do(r.Context(), func(context.Context) error {
		writer := flowio.NewWriter(&body)
		for _, f := range a.view.Flows() {
			if filter.Match(expression, f) {
				if err := writer.Add(f); err != nil {
					return err
				}
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	w.Header().Set("Content-Disposition", "attachment; filename=flows")
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.Itoa(body.Len()))
	_, err = w.Write(body.Bytes())
	return err
}

var transparentPNG = []byte("\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x04\x00\x00\x00\xb5\x1c\x0c\x02\x00\x00\x00\x0bIDATx\xdac\xfc\xff\x07\x00\x02\x00\x01\xfc\xa8Q\rh\x00\x00\x00\x00IEND\xaeB`\x82")

var filterHelp = [][2]string{
	{"~a", "Match asset in response: CSS, JavaScript, images, fonts."}, {"~all", "Match all flows"}, {"~b regex", "Body"}, {"~bq regex", "Request body"}, {"~bs regex", "Response body"}, {"~c int", "HTTP response code"}, {"~comment regex", "Flow comment"}, {"~d regex", "Domain"}, {"~dns", "Match DNS flows"}, {"~dst regex", "Match destination address"}, {"~e", "Match error"}, {"~h regex", "Header"}, {"~hq regex", "Request header"}, {"~hs regex", "Response header"}, {"~http", "Match HTTP flows"}, {"~m regex", "Method"}, {"~marked", "Match marked flows"}, {"~marker regex", "Match marked flows with specified marker"}, {"~meta regex", "Flow metadata"}, {"~q", "Match request with no response"}, {"~replay", "Match replayed flows"}, {"~replayq", "Match replayed client request"}, {"~replays", "Match replayed server response"}, {"~s", "Match response"}, {"~src regex", "Match source address"}, {"~t regex", "Content-type header"}, {"~tcp", "Match TCP flows"}, {"~tq regex", "Request Content-Type header"}, {"~ts regex", "Response Content-Type header"}, {"~u regex", "URL"}, {"~udp", "Match UDP flows"}, {"~websocket", "Match WebSocket flows"}, {"!", "unary not"}, {"&", "and"}, {"|", "or"}, {"(...)", "grouping"},
}
