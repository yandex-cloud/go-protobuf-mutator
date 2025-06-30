package mutator

import (
	"google.golang.org/protobuf/proto"
)

// Mutator mutates values inplace
// MutateString and MutateBytes return new mutated value
type Mutator interface {
	MutateProto(msg proto.Message) error
	MutateBool(value *bool) error
	MutateFloat64(value *float64) error
	MutateFloat32(value *float32) error
	MutateUint32(value *uint32) error
	MutateUint64(value *uint64) error
	MutateInt32(value *int32) error
	MutateInt64(value *int64) error
	MutateString(str string, maxSize int) (string, error)
	MutateBytes(value []byte, maxSize int) ([]byte, error)
}
