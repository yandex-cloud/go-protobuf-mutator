package main

import (
	"bytes"
	"context"
	"fmt"

	"github.com/yandex-cloud/go-protobuf-mutator/example/service"

	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	pb "github.com/yandex-cloud/go-protobuf-mutator/testdata"
)

func ParseProtoMessage(data []byte) ([]byte, handler, proto.Message, error) {
	var method, encoded []byte

	parsed := bytes.SplitN(data, []byte("\n"), 2)
	method = parsed[0]

	if len(parsed) == 2 {
		encoded = parsed[1]
	}

	// Load proto message
	handler, ok := handlerMap[string(method)]
	if !ok {
		return method, handler, nil, nil
	}

	message := handler.message()
	if err := prototext.Unmarshal(encoded, message); err != nil {
		return method, handler, nil, err
	}

	return method, handler, message, nil
}

func StoreMessage(data, method []byte, message protoreflect.ProtoMessage) (int, error) {
	mutated := make([]byte, len(data))
	formatted := []byte(prototext.MarshalOptions{
		Multiline: true,
	}.Format(message))

	size := len(method) + len(formatted) + 1
	if size > len(data) {
		return 0, fmt.Errorf("Stored size must be less than data size: %d > %d", size, len(data))
	}

	// NOTE: new size might be less than input size
	// we should rewrite the whole block with new data
	copy(mutated, method)
	mutated[len(method)] = '\n'
	copy(mutated[len(method)+1:], formatted)

	copy(data, mutated)

	return size, nil
}

type handler struct {
	message func() proto.Message
	fuzz    func(context.Context, string, proto.Message) error
}

var handlerMap = map[string]handler{
	"ExampleService/Get": {
		message: func() proto.Message { return &pb.RequestMessage{} },
		fuzz:    service.FuzzGet,
	},
}
