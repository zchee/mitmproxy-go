// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package commander

import (
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/internal/pyrepr"
	"github.com/zchee/mitmproxy-go/internal/tools/console/internal/contract"
	"github.com/zchee/mitmproxy-go/options"
)

// CommandPrompt prepares the quoted starting value of console.command.
func CommandPrompt(arguments ...string) contract.Action {
	words := make([]string, len(arguments))
	for i, argument := range arguments {
		words[i] = command.Quote(argument)
	}
	text := strings.Join(words, " ")
	if text != "" {
		text += " "
	}
	return contract.Action{Kind: "prompt", Value: "command", Text: text, Index: utf8.RuneCountInString(text)}
}

// OptionPrompt places the cursor inside the current option's quoted representation.
func OptionPrompt(option options.Option) contract.Action {
	value := option.Current()
	switch current := value.(type) {
	case nil:
		value = ""
	case bool:
		if !current {
			value = ""
		}
	case int:
		if current == 0 {
			value = ""
		}
	case *string:
		if current == nil {
			value = ""
		} else {
			value = *current
		}
	case *int:
		if current == nil || *current == 0 {
			value = ""
		} else {
			value = *current
		}
	}
	text := "set " + option.Name() + " " + pyrepr.Value(value)
	return contract.Action{Kind: "prompt", Value: "command", Text: text, Index: max(0, utf8.RuneCountInString(text)-1)}
}

// ChoicePrompt captures all replacement locations without retaining a call context.
func ChoicePrompt(title string, values []string, commandName string, arguments []string) contract.Action {
	choices := make([]contract.Choice, len(values))
	for i, value := range values {
		choices[i] = contract.Choice{Label: value, Value: value}
	}
	recipe := contract.Recipe{Command: commandName, Arguments: slices.Clone(arguments)}
	for i, argument := range arguments {
		if strings.Contains(argument, "{choice}") {
			recipe.ChoiceIndices = append(recipe.ChoiceIndices, i)
		}
	}
	return contract.Action{Kind: "prompt", Value: "choice", Text: title, Choices: choices, Recipe: recipe}
}

// ConfirmPrompt prepares a yes/no prompt; declining never invokes the recipe.
func ConfirmPrompt(title, commandName string, arguments []string) contract.Action {
	return contract.Action{Kind: "prompt", Value: "confirm", Text: title, Choices: []contract.Choice{{Label: "Yes", Value: "y"}, {Label: "No", Value: "n"}}, Recipe: contract.Recipe{Command: commandName, Arguments: slices.Clone(arguments)}}
}
