# Mutator Usage Examples

## Quick Start Example

### Running the Basic Example

```sh
make build-docker

docker run --rm --network=host -it -v "$PWD/../.:/workdir" -w /workdir/example \
    fuzzing:v1.0.0 \
    /bin/bash -exc 'cp -r initial-corpus/ corpus; make coverage DURATION=60; cat result_func.txt'
```

## Coverage Tracking Implementation

The library provides integrated support for Go's native code coverage instrumentation during fuzzing operations, enabling precise coverage data collection.

### Basic Implementation

```go
func FuzzWithCoverage() {
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()
    
    // Initialize background coverage tracking
    go DumpCoverage(ctx)
    
    // Core fuzzing loop
    for {
        msg := GenerateTestMessage()
        mutator.MutateProto(msg)
        TestFunction(msg)
    }
}
```

### Architecture Overview

The coverage tracking system:

1. **Periodic Data Export** (10s intervals):
   - `covmeta.data` → Coverage instrumentation metadata
   - `covcounters.data.1.1` → Actual coverage counters

2. **Optimized Storage**:
   - Files are overwritten cyclically to conserve disk space
   - Background operation until explicit context cancellation

### Coverage Analysis Workflow

Post-fuzzing data processing:

```bash
# Convert binary coverage data to text format
go tool covdata textfmt -i covcounters.data.1.1 -o coverage.txt

# Generate visual HTML report
go tool cover -html=coverage.txt -o coverage.html
```

### Advanced Integration with libFuzzer

For comprehensive fuzzing setups:

```go
//export LLVMFuzzerInitialize
func LLVMFuzzerInitialize(argc *C.int, argv ***C.char) C.int {
	ctx := context.Background()
	go DumpCoverage(ctx)

	// add init

	return 0
}

//export LLVMFuzzerTestOneInput
func LLVMFuzzerTestOneInput(data *C.uchar, size C.size_t) C.int {
    ctx := context.Background()
    
    // Core fuzzing logic
    return 0
}

//export LLVMFuzzerCustomMutator
func LLVMFuzzerCustomMutator(data *C.char, size C.size_t, maxSize C.size_t, seed C.uint) C.size_t {
	// convert to golang structure with underlaying storage on C structure
	gdata := unsafe.Slice((*byte)(unsafe.Pointer(data)), size)

	// Load proto message
	message := ParseProtoMessage(gdata)

	mutator := mutator.New(int64(seed), int(maxSize-size))
	if err := mutator.MutateProto(message); err != nil {
		fmt.Printf("Failed to mutate message: %+v", err)
		return 0
	}

	gdata = unsafe.Slice((*byte)(unsafe.Pointer(data)), maxSize)

	// copy result back to C storage
	newSize := StoreMessage(gdata, message)
	return C.size_t(newSize)
}
```
