package mutator

import (
	testdata "go-protobuf-mutator/testdata"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
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
