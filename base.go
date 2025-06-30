package mutator

import (
	"encoding/binary"
	"math/rand"
	"unsafe"
)

var nativeEndian binary.ByteOrder

func init() {
	buf := [2]byte{}
	*(*uint16)(unsafe.Pointer(&buf[0])) = uint16(0xABCD)

	switch buf {
	case [2]byte{0xCD, 0xAB}:
		nativeEndian = binary.LittleEndian
	case [2]byte{0xAB, 0xCD}:
		nativeEndian = binary.BigEndian
	default:
		panic("Could not determine native endian.")
	}
}

// Return random integer from [0, count)
func getRandomRange(src *rand.Rand, count int) int {
	// validate count
	// because rand panics if count <= 0
	if count <= 0 {
		return 0
	}
	return src.Intn(count)
}

func MutateInt64(src *rand.Rand, value *int64) error {
	return mutateValue(src, value)
}

func MutateInt32(src *rand.Rand, value *int32) error {
	return mutateValue(src, value)
}

func MutateUint64(src *rand.Rand, value *uint64) error {
	return mutateValue(src, value)
}

func MutateUint32(src *rand.Rand, value *uint32) error {
	return mutateValue(src, value)
}

func MutateFloat32(src *rand.Rand, value *float32) error {
	return mutateValue(src, value)
}

func MutateFloat64(src *rand.Rand, value *float64) error {
	return mutateValue(src, value)
}

func MutateBool(src *rand.Rand, value *bool) error {
	return mutateValue(src, value)
}

// Return random bool value
func GetRandomBool(src *rand.Rand) bool {
	return GetRandomBoolN(src, 2)
}

// Return true with probability about 1-of-n.
func GetRandomBoolN(src *rand.Rand, n int) bool {
	val := getRandomRange(src, n)
	return val == 0
}

// Flips random bit in the buffer.
func flipBit(src *rand.Rand, size int, data []byte) {
	if len(data) == 0 {
		return
	}
	bit := getRandomRange(src, size*8)

	data[bit/8] ^= (1 << (bit % 8))
}
