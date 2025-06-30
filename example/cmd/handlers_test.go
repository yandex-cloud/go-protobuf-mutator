package main

import (
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	pb "go-protobuf-mutator/testdata"
)

func TestParseProtoMessage(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want proto.Message
	}{
		{
			name: "simple",
			data: []byte(`ExampleService/Get
				required_field: "required"`),
			want: &pb.RequestMessage{
				RequiredField: "required",
			},
		},
		{
			name: "empty",
			data: []byte(`ExampleService/Get`),
			want: &pb.RequestMessage{},
		},
		{
			name: "empty with new line",
			data: []byte(`ExampleService/Get
`),
			want: &pb.RequestMessage{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, got, err := ParseProtoMessage(tt.data)
			require.NoError(t, err)

			if !proto.Equal(tt.want, got) {
				t.Errorf("ParseProtoMessage() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestStoreMessage(t *testing.T) {
	tests := []struct {
		name     string
		method   []byte
		data     []byte
		message  protoreflect.ProtoMessage
		expected proto.Message
	}{
		{
			name:   "simple",
			method: []byte(`ExampleService/Get`),
			data:   make([]byte, 100),
			message: &pb.RequestMessage{
				RequiredField: "required",
			},
			expected: &pb.RequestMessage{
				RequiredField: "required",
			},
		},
		{
			name:     "empty",
			method:   []byte("ExampleService/Get"),
			data:     make([]byte, 100),
			message:  &pb.RequestMessage{},
			expected: &pb.RequestMessage{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			size, err := StoreMessage(tt.data, tt.method, tt.message)
			require.NoError(t, err)
			_, _, got, err := ParseProtoMessage(tt.data[:size])
			require.NoError(t, err)

			if !proto.Equal(tt.expected, got) {
				t.Errorf("ParseProtoMessage() = %v, want %v", got, tt.expected)
			}
		})
	}
}
