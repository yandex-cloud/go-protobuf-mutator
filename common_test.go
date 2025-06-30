//go:build !libfuzzer

package mutator

import (
	"math/rand"
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestFlipBitValue(t *testing.T) {
	src := rand.New(rand.NewSource(time.Now().Unix()))

	var (
		valueInt32   = int32(32)
		valueInt64   = int64(64)
		valueUint32  = uint32(32)
		valueUint64  = uint64(64)
		valueFloat32 = float32(32)
		valueFloat64 = float64(64)
		valueBool    = true
	)

	tests := []struct {
		name  string
		value any
	}{
		{
			"int32",
			&valueInt32,
		},
		{
			"int64",
			&valueInt64,
		},
		{
			"uint32",
			&valueUint32,
		},
		{
			"uint64",
			&valueUint64,
		},
		{
			"float32",
			&valueFloat32,
		},
		{
			"float64",
			&valueFloat64,
		},
		{
			"bool",
			&valueBool,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for run := 0; run < 10000; run++ {
				value := reflect.ValueOf(tt.value)
				require.NoError(t, mutateValue(src, tt.value))
				require.NotEqualValues(t, value, tt.value)
			}
		})
	}
}
