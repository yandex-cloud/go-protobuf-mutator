## Go protobuf mutator  

This is a go-protobuf-mutator library for random value mutations. This is a Go equivalent of [libprotobuf-mutator](https://github.com/google/libprotobuf-mutator), which is implemented in C++.

### Supported Types  
- ProtoMessage  
- Bool  
- Float64  
- Float32  
- Uint32  
- Uint64  
- Int32  
- Int64  
- String  
- Bytes  

### Dependencies for libfuzzer
- Go 1.21+
- Protocol Buffers compiler (`protoc`)
- libprotobuf-dev
- clang (for libFuzzer integration)
- libprotobuf-mutator (v1.1)

### Generating Protocol Buffer Files

Generate Go code from your `.proto` files using the `protoc` compiler:

```sh
protoc --go_out=. --go-grpc_out=. testdata/example.proto
```

This will generate both the standard protocol buffer code (`.pb.go`) and gRPC service definitions (`.grpc.pb.go`) if your proto file contains service definitions.

**Resources:**
- [Protocol Buffers Official Documentation](https://protobuf.dev/)
- [Go Protocol Buffers Library](https://pkg.go.dev/google.golang.org/protobuf)

### Basic Usage
```go
message := NewProtoMessage()
mutator := mutator.New(int64(seed), maxSize)
if err := mutator.MutateProto(message); err != nil {
    fmt.Printf("Failed to mutate message: %+v", err)
}
```

### Implementation Examples

For complete reference implementations:

| Feature               | Location                          | Documentation                       |
|-----------------------|-----------------------------------|-------------------------------------|
| libFuzzer Integration | [`example/cmd/libfuzzer.go`](./example/cmd/libfuzzer.go) | [README](./example/README.md) |
| Coverage Tracking     | [`example/cmd/coverage.go`](./example/cmd/coverage.go) | Code comments            |

**Pro Tip**: The libFuzzer example includes:
- Custom mutator setup
- Seed corpus generation
- Crash reproduction workflow
- Performance benchmarking

### Integration with libFuzzer  
Add `--tag libfuzzer` to build commands when using libFuzzer.  

#### Example Code  
```go  
// #include <stdint.h>
import "C"

//export LLVMFuzzerTestOneInput
func LLVMFuzzerTestOneInput(data *C.char, size C.size_t) C.int {
    gdata := unsafe.Slice((*byte)(unsafe.Pointer(data)), size)
    message := NewProtoMessage(gdata)
    Fuzz(message)
    return 0
}

//export LLVMFuzzerCustomMutator
func LLVMFuzzerCustomMutator(data *C.char, size C.size_t, maxSize C.size_t, seed C.uint) C.size_t {
    gdata := unsafe.Slice((*byte)(unsafe.Pointer(data)), size)
    message := NewProtoMessage(gdata)

    mutator := mutator.New(int64(seed), int(maxSize-size))
    if err := mutator.MutateProto(message); err != nil {
        return 0
    }

    gdata = unsafe.Slice((*byte)(unsafe.Pointer(data)), maxSize)
    newSize := StoreMessage(gdata, message)
    return C.size_t(newSize)
}
```  

#### Build Commands  
```sh
go build -tags libfuzzer -buildmode c-archive -o fuzz.a ./cmd/fuzzing
clang++ -o fuzz fuzz.a -fsanitize=fuzzer
./fuzz ./corpus
```
