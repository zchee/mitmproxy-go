// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package contentviews

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math"
	"strings"

	yaml "go.yaml.in/yaml/v4"
	"go.yaml.in/yaml/v4/plugin/limit"
)

// LimitError identifies a contentview resource refusal without including input.
type LimitError struct {
	View, Stage, Resource string
	Limit, Attempted      uint64
}

// Error reports the view, stage and exhausted resource.
func (e *LimitError) Error() string {
	return fmt.Sprintf("%s: %s: %s limit exceeded (%d > %d)", e.View, e.Stage, e.Resource, e.Attempted, e.Limit)
}

type viewLimits struct {
	InputBytes, OutputBytes, DecompressedBytes, Nodes uint64
	Depth                                             int
}

type viewBudget struct {
	view                                      string
	limits                                    viewLimits
	nodes, output, decompressed, materialized uint64
}

func newViewBudget(view string) *viewBudget {
	return &viewBudget{view: view, limits: viewLimits{
		InputBytes: 64 << 20, OutputBytes: 64 << 20,
		DecompressedBytes: 64 << 20, Nodes: 1_000_000, Depth: 64,
	}}
}

func (b *viewBudget) refusal(stage, resource string, used, count, maximum uint64) error {
	attempted := uint64(math.MaxUint64)
	if count <= math.MaxUint64-used {
		attempted = used + count
	}
	return &LimitError{View: b.view, Stage: stage, Resource: resource, Limit: maximum, Attempted: attempted}
}

func (b *viewBudget) charge(stage, resource string, used *uint64, count, maximum uint64) error {
	if *used > maximum || count > maximum-*used {
		return b.refusal(stage, resource, *used, count, maximum)
	}
	*used += count
	return nil
}

func (b *viewBudget) checkInput(stage string, size uint64) error {
	if size > b.limits.InputBytes {
		return b.refusal(stage, "input bytes", 0, size, b.limits.InputBytes)
	}
	return nil
}

func (b *viewBudget) chargeNodes(stage string, count uint64) error {
	return b.charge(stage, "logical nodes", &b.nodes, count, b.limits.Nodes)
}

func (b *viewBudget) chargeDecompressed(stage string, size uint64) error {
	return b.charge(stage, "decompressed bytes", &b.decompressed, size, b.limits.DecompressedBytes)
}

func (b *viewBudget) checkOutput(stage string, size uint64) error {
	if b.output > b.limits.OutputBytes || size > b.limits.OutputBytes-b.output {
		return b.refusal(stage, "output bytes", b.output, size, b.limits.OutputBytes)
	}
	return nil
}

func (b *viewBudget) chargeOutput(stage string, size uint64) error {
	return b.charge(stage, "output bytes", &b.output, size, b.limits.OutputBytes)
}

func (b *viewBudget) chargeMaterialization(stage string, size uint64) error {
	return b.charge(stage, "materialized bytes", &b.materialized, size, b.limits.OutputBytes)
}

func (b *viewBudget) checkDepth(stage string, depth int) error {
	if depth > b.limits.Depth {
		return b.refusal(stage, "nesting depth", 0, uint64(depth), uint64(max(b.limits.Depth, 0)))
	}
	return nil
}

type yamlAnchorWeight struct {
	weight uint64
	height int
	active bool
}

type yamlWeightFrame struct {
	kind   yaml.NativeEventKind
	weight uint64
	height int
	anchor *yamlAnchorWeight
}

func preflightYAML(data []byte, budget *viewBudget) error {
	const stage = "YAML preflight"
	if err := budget.checkInput(stage, uint64(len(data))); err != nil {
		return err
	}
	anchors := make(map[string]*yamlAnchorWeight)
	var frames []yamlWeightFrame
	var nativeDepthError error
	depthOption := yaml.WithPlugin(limit.New(limit.DepthFunc(func(depth int, _ *yaml.DepthContext) error {
		err := budget.checkDepth(stage, depth)
		if err != nil {
			nativeDepthError = err
		}
		return err
	})))
	addWeight := func(weight uint64, height int) {
		if len(frames) != 0 {
			parent := &frames[len(frames)-1]
			parent.weight += weight
			parent.height = max(parent.height, 1+height)
		}
	}
	err := yaml.ScanNativeEvents(bytes.NewReader(data), func(event yaml.NativeEvent) error {
		switch event.Kind {
		case yaml.NativeStreamStart, yaml.NativeStreamEnd, yaml.NativeTailComment:
			return nil
		case yaml.NativeDocumentStart:
			clear(anchors)
			if len(frames) != 0 {
				return fmt.Errorf("%s: %s: inconsistent document boundary", budget.view, stage)
			}
			return budget.chargeNodes(stage, 1)
		case yaml.NativeDocumentEnd:
			if len(frames) != 0 {
				return fmt.Errorf("%s: %s: unclosed collection", budget.view, stage)
			}
			return nil
		case yaml.NativeSequenceEnd, yaml.NativeMappingEnd:
			if len(frames) == 0 {
				return fmt.Errorf("%s: %s: unmatched collection boundary", budget.view, stage)
			}
			frame := frames[len(frames)-1]
			if (event.Kind == yaml.NativeSequenceEnd && frame.kind != yaml.NativeSequenceStart) ||
				(event.Kind == yaml.NativeMappingEnd && frame.kind != yaml.NativeMappingStart) {
				return fmt.Errorf("%s: %s: mismatched collection boundary", budget.view, stage)
			}
			frames = frames[:len(frames)-1]
			if frame.anchor != nil {
				frame.anchor.weight, frame.anchor.height, frame.anchor.active = frame.weight, frame.height, false
			}
			addWeight(frame.weight, frame.height)
			return nil
		case yaml.NativeScalar, yaml.NativeSequenceStart, yaml.NativeMappingStart, yaml.NativeAlias:
			if err := budget.chargeNodes(stage, 1); err != nil {
				return err
			}
		default:
			return fmt.Errorf("%s: %s: unknown native event", budget.view, stage)
		}
		if event.Kind == yaml.NativeAlias {
			anchor, found := anchors[string(event.Anchor)]
			if !found || anchor == nil {
				return fmt.Errorf("%s: %s: undefined alias", budget.view, stage)
			}
			if anchor.active {
				return fmt.Errorf("%s: %s: cyclic alias", budget.view, stage)
			}
			if err := budget.checkDepth(stage, len(frames)+anchor.height); err != nil {
				return err
			}
			if err := budget.chargeNodes(stage, anchor.weight); err != nil {
				return err
			}
			addWeight(1+anchor.weight, anchor.height)
			return nil
		}
		var anchor *yamlAnchorWeight
		if len(event.Anchor) != 0 {
			if err := budget.chargeMaterialization(stage, uint64(len(event.Anchor))); err != nil {
				return err
			}
			anchor = &yamlAnchorWeight{weight: 1}
			anchors[string(event.Anchor)] = anchor
		}
		if event.Kind == yaml.NativeScalar {
			addWeight(1, 0)
			return nil
		}
		if err := budget.checkDepth(stage, len(frames)+1); err != nil {
			return err
		}
		if anchor != nil {
			anchor.active = true
		}
		frames = append(frames, yamlWeightFrame{kind: event.Kind, weight: 1, height: 1, anchor: anchor})
		return nil
	}, depthOption)
	if nativeDepthError != nil {
		if loadError, ok := errors.AsType[*yaml.LoadError](err); ok && loadError.Stage == yaml.ScannerStage {
			return nativeDepthError
		}
	}
	return err
}

func parseBoundedYAML(data []byte, budget *viewBudget) ([]*yaml.Node, error) {
	return parseBoundedYAMLWithLoader(data, budget, yaml.NewLoader)
}

func parseBoundedYAMLWithLoader(data []byte, budget *viewBudget, create func(io.Reader, ...yaml.Option) (*yaml.Loader, error)) ([]*yaml.Node, error) {
	if err := budget.checkInput("YAML snapshot", uint64(len(data))); err != nil {
		return nil, err
	}
	snapshot := bytes.Clone(data)
	if err := preflightYAML(snapshot, budget); err != nil {
		return nil, err
	}
	loader, err := create(bytes.NewReader(snapshot), yaml.WithPlugin(limit.New(limit.DepthValue(budget.limits.Depth))))
	if err != nil {
		return nil, err
	}
	var documents []*yaml.Node
	for {
		var node yaml.Node
		if err := loader.Load(&node); err != nil {
			if errors.Is(err, io.EOF) {
				return documents, nil
			}
			return nil, err
		}
		documents = append(documents, &node)
	}
}

type boundedViewWriter struct {
	dst    io.Writer
	budget *viewBudget
}

func newBoundedViewWriter(dst io.Writer, budget *viewBudget) *boundedViewWriter {
	return &boundedViewWriter{dst: dst, budget: budget}
}

func (w *boundedViewWriter) Write(p []byte) (int, error) {
	if err := w.budget.chargeOutput("YAML output", uint64(len(p))); err != nil {
		return 0, err
	}
	n, err := w.dst.Write(p)
	if n != len(p) && err == nil {
		err = io.ErrShortWrite
	}
	return n, err
}

type yamlEmitOptions struct {
	InlineCommentGap int
}

// A marker in cloned comment metadata identifies spacing changes without
// recognizing YAML syntax or touching hashes in scalar text. NUL is never
// forwarded: original comments containing it are refused before serialization.
type yamlCommentGapWriter struct {
	dst         *boundedViewWriter
	pendingHash bool
	lineText    bool
	extra       int
	buffer      [4096]byte
	buffered    int
}

func (w *yamlCommentGapWriter) flush() error {
	if w.buffered == 0 {
		return nil
	}
	_, err := w.dst.Write(w.buffer[:w.buffered])
	w.buffered = 0
	return err
}

func (w *yamlCommentGapWriter) put(c byte) error {
	if w.buffered == len(w.buffer) {
		if err := w.flush(); err != nil {
			return err
		}
	}
	if err := w.dst.budget.checkOutput("YAML comment spacing", uint64(w.buffered+1)); err != nil {
		return err
	}
	w.buffer[w.buffered] = c
	w.buffered++
	if c == '\n' {
		w.lineText = false
	} else if c != ' ' && c != '\t' && c != '\r' {
		w.lineText = true
	}
	return nil
}

func (w *yamlCommentGapWriter) Write(p []byte) (int, error) {
	for i, c := range p {
		if w.pendingHash {
			w.pendingHash = false
			if c == 0 {
				if w.lineText {
					for range w.extra {
						if err := w.put(' '); err != nil {
							return i, err
						}
					}
				}
				if err := w.put('#'); err != nil {
					return i, err
				}
				continue
			}
			if err := w.put('#'); err != nil {
				return i, err
			}
		}
		if c == '#' {
			w.pendingHash = true
		} else if err := w.put(c); err != nil {
			return i, err
		}
	}
	return len(p), nil
}

func (w *yamlCommentGapWriter) finish() error {
	if w.pendingHash {
		w.pendingHash = false
		if err := w.put('#'); err != nil {
			return err
		}
	}
	return w.flush()
}

func cloneBoundedYAML(node *yaml.Node, budget *viewBudget, gap int) (*yaml.Node, error) {
	active := make(map[*yaml.Node]bool)
	var clone func(*yaml.Node, int) (*yaml.Node, error)
	clone = func(node *yaml.Node, depth int) (*yaml.Node, error) {
		if node == nil {
			return nil, fmt.Errorf("%s: YAML emission: nil node", budget.view)
		}
		if active[node] {
			return nil, fmt.Errorf("%s: YAML emission: cyclic node graph", budget.view)
		}
		if err := budget.chargeNodes("YAML emission", 1); err != nil {
			return nil, err
		}
		if node.Kind == yaml.SequenceNode || node.Kind == yaml.MappingNode {
			depth++
		}
		if err := budget.checkDepth("YAML emission", depth); err != nil {
			return nil, err
		}
		for _, comment := range []string{node.HeadComment, node.LineComment, node.FootComment} {
			if strings.ContainsRune(comment, 0) {
				return nil, fmt.Errorf("%s: YAML emission: invalid comment character", budget.view)
			}
		}
		if err := budget.checkInput("YAML tag", uint64(len(node.Tag))); err != nil {
			return nil, err
		}
		for _, field := range []string{node.Value, node.Anchor, node.HeadComment, node.LineComment, node.FootComment} {
			if err := budget.chargeMaterialization("YAML emission", uint64(len(field))); err != nil {
				return nil, err
			}
		}
		active[node] = true
		defer delete(active, node)
		copy := *node
		copy.Content = nil
		copy.Alias = nil
		if gap > 1 && copy.LineComment != "" {
			comment, hasHash := strings.CutPrefix(copy.LineComment, "#")
			if !hasHash {
				comment = " " + comment
			}
			copy.LineComment = "#\x00" + comment
		}
		for _, child := range node.Content {
			next, err := clone(child, depth)
			if err != nil {
				return nil, err
			}
			copy.Content = append(copy.Content, next)
		}
		if node.Alias != nil {
			next, err := clone(node.Alias, depth)
			if err != nil {
				return nil, err
			}
			copy.Alias = next
		}
		return &copy, nil
	}
	return clone(node, 0)
}

func emitBoundedYAML(dst *boundedViewWriter, node *yaml.Node, opts yamlEmitOptions) error {
	if opts.InlineCommentGap < 0 || opts.InlineCommentGap > 2 {
		return fmt.Errorf("%s: YAML emission: comment gap must be 0, 1 or 2", dst.budget.view)
	}
	copy, err := cloneBoundedYAML(node, dst.budget, opts.InlineCommentGap)
	if err != nil {
		return err
	}
	var output io.Writer = dst
	var comments *yamlCommentGapWriter
	if opts.InlineCommentGap > 1 {
		comments = &yamlCommentGapWriter{dst: dst, extra: opts.InlineCommentGap - 1}
		output = comments
	}
	dumper, err := yaml.NewDumper(output, yaml.WithV4Defaults(), yaml.WithLineWidth(-1))
	if err != nil {
		return err
	}
	if err := dumper.Dump(copy); err != nil {
		return err
	}
	if err := dumper.Close(); err != nil {
		return err
	}
	if comments != nil {
		return comments.finish()
	}
	return nil
}

func dumpBoundedYAML(node *yaml.Node, budget *viewBudget, opts yamlEmitOptions) (string, error) {
	var output strings.Builder
	writer := newBoundedViewWriter(&output, budget)
	if err := emitBoundedYAML(writer, node, opts); err != nil {
		return "", err
	}
	return output.String(), nil
}
