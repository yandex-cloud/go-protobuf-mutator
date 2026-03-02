package mutator

import (
	"testing"
	"time"

	testdata "github.com/yandex-cloud/go-protobuf-mutator/testdata"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/dynamicpb"
)

const (
	B  uint64 = 1
	KB        = B << 10
	MB        = KB << 10
)

func Test_mutator_Mutate(t *testing.T) {
	tests := []struct {
		name string
		msg  proto.Message
	}{
		{
			"empty",
			&testdata.RequestMessage{},
		},
		{
			"test data",
			&testdata.RequestMessage{
				RequiredField: "field",
				ValidMap: map[string]string{
					"foo":  "bard",
					"foo2": "bard",
					"fo":   "bard",
				},
				ValidField:    100500,
				LengthField1:  []string{"2", "4"},
				ValidRepeated: []string{"1", "2", "fasdfasfd", "fasdf"},
				OneofField: &testdata.RequestMessage_NestedMessage_{
					NestedMessage: &testdata.RequestMessage_NestedMessage{
						Field: "fieldsfsdfsfsfsfsdfs",
					},
				},
			},
		},
		{
			"other",
			&testdata.RequestMessage{
				RequiredField: "field",
				ValidMap: map[string]string{
					"foo":  "bard",
					"foo2": "bard",
					"fo":   "bard",
				},
				ValidRepeated: []string{"1", "2", "fasdfasfd", "fasdf"},
				OneofField: &testdata.RequestMessage_OneofInner{
					OneofInner: &testdata.InnerMessage{
						InnnerId:      "innder-one-of-id",
						InnerRepeated: []string{"one-of-innter", "one-of-repeated"},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := New(time.Now().Unix(), int(MB))
			tmp := proto.Clone(tt.msg)
			for range 100 {
				require.NoError(t, m.MutateProto(tt.msg))
			}

			require.False(t, proto.Equal(tmp, tt.msg))
		})
	}
}

func Test_mutator_MutateDynamicProtoWithInt32(t *testing.T) {
	typedMsg := &testdata.Int32Message{
		Value1: 10,
	}

	// Get the descriptor from the typed message
	desc := typedMsg.ProtoReflect().Descriptor()
	// Create a new dynamic message with that descriptor
	dynMsg := dynamicpb.NewMessage(desc)
	// Copy data from the original to the dynamic message
	proto.Merge(dynMsg, typedMsg)

	// Create a mutator
	m := New(time.Now().Unix(), int(MB))
	require.NoError(t, m.MutateProto(dynMsg))
}

func Test_mutator_MutateDynamicProtoWithUInt32(t *testing.T) {
	typedMsg := &testdata.UInt32Message{
		Value1: 10,
	}

	// Get the descriptor from the typed message
	desc := typedMsg.ProtoReflect().Descriptor()
	// Create a new dynamic message with that descriptor
	dynMsg := dynamicpb.NewMessage(desc)
	// Copy data from the original to the dynamic message
	proto.Merge(dynMsg, typedMsg)

	// Create a mutator
	m := New(time.Now().Unix(), int(MB))
	require.NoError(t, m.MutateProto(dynMsg))
}
