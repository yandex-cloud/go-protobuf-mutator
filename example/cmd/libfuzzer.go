//go:build libfuzzer
// +build libfuzzer

package main

import (
	"context"
	"fmt"
	"unsafe"

	mutator "go-protobuf-mutator"
)

// #include <stdint.h>
import "C"

//export LLVMFuzzerTestOneInput
func LLVMFuzzerTestOneInput(data *C.char, size C.size_t) C.int {
	ctx := context.Background()
	// convert to golang structure with underlaying storage on C structure
	gdata := unsafe.Slice((*byte)(unsafe.Pointer(data)), size)

	// Load proto message
	method, handler, message, err := ParseProtoMessage(gdata)
	if err != nil {
		fmt.Printf("Failed to parse proto message: %+v", err)
		return 0
	}
	if message == nil {
		fmt.Printf("Got empty message: method %s", string(method))
		return 0
	}

	if err := handler.fuzz(ctx, string(method), message); err != nil {
		// put your logic here to validate invalid response from server

		fmt.Printf("API result from fuzzer: %+v", err)
		panic("API error")
	}

	return 0
}

//export LLVMFuzzerInitialize
func LLVMFuzzerInitialize(argc *C.int, argv ***C.char) C.int {
	ctx := context.Background()
	go DumpCoverage(ctx)

	// add init

	return 0
}

//export LLVMFuzzerCustomMutator
func LLVMFuzzerCustomMutator(data *C.char, size C.size_t, maxSize C.size_t, seed C.uint) C.size_t {
	// convert to golang structure with underlaying storage on C structure
	gdata := unsafe.Slice((*byte)(unsafe.Pointer(data)), size)

	// Load proto message
	method, _, message, err := ParseProtoMessage(gdata)
	if err != nil {
		fmt.Printf("Failed to parse proto message: %+v", err)
		return 0
	}
	if message == nil {
		method := []byte("ExampleService/Get\n")
		copy(gdata, method)
		return C.size_t(len(method))
	}

	mutator := mutator.New(int64(seed), int(maxSize-size))
	if err := mutator.MutateProto(message); err != nil {
		fmt.Printf("Failed to mutate message: %+v", err)
		return 0
	}

	gdata = unsafe.Slice((*byte)(unsafe.Pointer(data)), maxSize)

	// copy result back to C storage
	newSize, err := StoreMessage(gdata, method, message)
	if err != nil {
		fmt.Printf("Failed to store new message: %+v", err)
		return 0
	}
	return C.size_t(newSize)
}
