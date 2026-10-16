// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package contentviewsdraft

import (
	"strings"

	"google.golang.org/protobuf/reflect/protoreflect"
)

func selectProtobufMessage(files []protoreflect.FileDescriptor, path string, request bool) protoreflect.MessageDescriptor {
	if !strings.ContainsRune(path, '?') {
		servicePath, methodName, found := strings.Cut(strings.TrimLeft(path, "/"), "/")
		if found && !strings.ContainsRune(methodName, '/') {
			packageName, serviceName, qualified := strings.CutLast(servicePath, ".")
			if !qualified {
				packageName, serviceName = "", servicePath
			}
			for _, file := range files {
				if string(file.Package()) != packageName {
					continue
				}
				service := file.Services().ByName(protoreflect.Name(serviceName))
				if service != nil {
					method := service.Methods().ByName(protoreflect.Name(methodName))
					if method != nil {
						return protobufMethodMessage(method, request)
					}
				}
				if message := file.Messages().ByName(protoreflect.Name(methodName)); message != nil {
					return message
				}
			}
		}
	}
	if len(files) == 0 {
		return nil
	}
	file := files[0]
	if services := file.Services(); services.Len() != 0 {
		if methods := services.Get(0).Methods(); methods.Len() != 0 {
			return protobufMethodMessage(methods.Get(0), request)
		}
	}
	if messages := file.Messages(); messages.Len() != 0 {
		return messages.Get(0)
	}
	return nil
}

func protobufMethodMessage(method protoreflect.MethodDescriptor, request bool) protoreflect.MessageDescriptor {
	if request {
		return method.Input()
	}
	return method.Output()
}
