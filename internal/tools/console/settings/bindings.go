// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package settings

import (
	"context"
	"slices"
	"strings"

	tea "charm.land/bubbletea/v2"

	"github.com/zchee/mitmproxy-go/internal/tools/console/commander"
	"github.com/zchee/mitmproxy-go/internal/tools/console/internal/contract"
	"github.com/zchee/mitmproxy-go/internal/tools/console/keymap"
	"github.com/zchee/mitmproxy-go/internal/tools/console/style"
)

// Bindings displays the current keymap and prepares editable binding commands.
type Bindings struct {
	ctx context.Context
	host contract.Host
	bindings []contract.Binding
	index,width,height int
	help bool
	err error
}

type bindingResult struct { owner *Bindings; err error }

var _ contract.Widget = (*Bindings)(nil)

// NewBindings returns a keybinding viewer backed by owned snapshots.
func NewBindings(ctx context.Context,host contract.Host) *Bindings {
	return &Bindings{ctx:ctx,host:host,width:80,height:24}
}

// SetSnapshot replaces the binding list while preserving the authoritative selection.
func (b *Bindings) SetSnapshot(s contract.Snapshot) {
	b.bindings=make([]contract.Binding,len(s.Bindings))
	for i,item:=range s.Bindings { item.Contexts=slices.Clone(item.Contexts);b.bindings[i]=item }
	if w,ok:=s.Control.Current("keybindings",false);ok { b.index,b.help=w.Index,w.Column==1 }
	b.index=min(max(b.index,0),max(0,len(b.bindings)-1))
}

// Resize sets the available dimensions.
func (b *Bindings) Resize(width,height int) { b.width,b.height=max(0,width),max(0,height) }

// Error returns the last binding action's error.
func (b *Bindings) Error() error { return b.err }

// Focused returns an owned binding and false when the help pane has focus.
func (b *Bindings) Focused() (contract.Binding,bool) {
	if b.help||len(b.bindings)==0 { return contract.Binding{},false }
	binding:=b.bindings[b.index]
	binding.Contexts=slices.Clone(binding.Contexts)
	return binding,true
}

func (b *Bindings) dispatch(action contract.Action) tea.Cmd {
	return func() tea.Msg { return bindingResult{owner:b,err:b.host.Dispatch(b.ctx,action)} }
}

// Update handles binding actions without executing typed prompt text.
func (b *Bindings) Update(msg tea.Msg) (tea.Cmd,bool) {
	if result,ok:=msg.(bindingResult);ok {
		if result.owner!=b{return nil,false}
		b.err=result.err
		return nil,true
	}
	key,ok:=msg.(tea.KeyPressMsg)
	if !ok {return nil,false}
	switch key.String() {
	case "up": b.index=max(0,b.index-1)
	case "down": b.index=min(max(0,len(b.bindings)-1),b.index+1)
	case "home": b.index=0
	case "end": b.index=max(0,len(b.bindings)-1)
	case "tab": b.help=!b.help
	case "a": return b.dispatch(commander.ChoicePrompt("Context",keymap.Contexts(),"console.command",[]string{"console.key.bind","{choice}"})),true
	case "enter", "x", "d":
		binding,ok:=b.Focused()
		if !ok {return nil,true}
		switch key.String() {
		case "enter": return b.dispatch(commander.CommandPrompt("console.key.bind",strings.Join(binding.Contexts,","),binding.Key,binding.Command)),true
		case "x": return b.dispatch(commander.CommandPrompt(binding.Command)),true
		case "d":
			return func() tea.Msg { _,err:=b.host.Call(b.ctx,"console.key.unbind",binding.Contexts,binding.Key);return bindingResult{owner:b,err:err} },true
		}
	default: return nil,false
	}
	index,column:=b.index,0
	if b.help {column=1}
	return b.dispatch(contract.Action{Kind:"selection",Index:index,Column:column}),true
}

// View renders a viewport of the current bindings and the focused help.
func (b *Bindings) View() string {
	if b.width==0||b.height==0{return ""}
	rows:=max(1,b.height-6)
	start:=max(0,b.index-rows+1)
	lines:=[]string{style.Fit("Key Bindings",b.width)}
	for i:=start;i<min(len(b.bindings),start+rows);i++ {
		binding:=b.bindings[i]
		prefix:="    "
		if i==b.index {prefix=">>  "}
		line:=prefix+style.Fit(style.Escape(binding.Key),10)+style.Fit(style.Escape(strings.Join(binding.Contexts,",")),12)+style.Escape(strings.TrimSpace(binding.Command))
		lines=append(lines,style.Fit(line,b.width))
	}
	if b.err!=nil{lines=append(lines,style.Fit(style.Escape(b.err.Error()),b.width))}
	if len(b.bindings)>0 {
		lines=append(lines,style.Fit("Key Binding Help",b.width))
		for line:=range strings.SplitSeq(style.Escape(b.bindings[b.index].Help),"\n"){lines=append(lines,style.Fit(line,b.width))}
	}
	return strings.Join(lines[:min(len(lines),b.height)],"\n")
}
