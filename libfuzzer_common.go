//go:build libfuzzer

package mutator

import (
	"bytes"
	"encoding/binary"
	"math/rand"
	"unsafe"
)

// #include <stdlib.h>
// extern size_t LLVMFuzzerMutate(char* Data, size_t Size, size_t MaxSize);
import "C"

func llvmFuzzerMutate(buffer []byte, size, maxSize int) []byte {
	cbuffer := C.malloc(C.size_t(maxSize))
	defer C.free(cbuffer)

	slice := ([]byte)(unsafe.Slice((*byte)(unsafe.Pointer(cbuffer)), maxSize))
	copy(slice, buffer)

	newSize := C.LLVMFuzzerMutate((*C.char)(cbuffer), C.size_t(size), C.size_t(maxSize))
	return C.GoBytes(cbuffer, C.int(newSize)) // copy result back to golang structures
}

// MutateValue using libfuzzer native mutator
// rand is for mutator compatibility
func mutateValue(src *rand.Rand, value any) error {
	size := int(unsafe.Sizeof(value))
	data := make([]byte, size)
	buf := bytes.NewBuffer(data)
	if err := binary.Write(buf, nativeEndian, value); err != nil {
		return err
	}

	mutated := llvmFuzzerMutate(buf.Bytes(), size, size)
	out := make([]byte, size) // mutated size can be less than required
	copy(out, mutated)

	if err := binary.Read(bytes.NewBuffer(out), nativeEndian, value); err != nil {
		return err
	}
	return nil
}

func MutateString(src *rand.Rand, value string, maxSize int) (string, error) {
	// Randomly return empty strings as LLVMFuzzerMutate does not produce them.
	if getRandomRange(src, 20) == 0 {
		return "", nil
	}
	mutated := llvmFuzzerMutate([]byte(value), len(value), maxSize)
	err := FixUTF8(mutated, src)
	return string(mutated), err
}

func MutateBytes(src *rand.Rand, value []byte, maxSize int) ([]byte, error) {
	mutated := llvmFuzzerMutate(value, len(value), maxSize)
	return mutated, nil
}
