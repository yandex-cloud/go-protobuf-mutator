//go:build !libfuzzer

package mutator

import (
	"bytes"
	"encoding/binary"
	"math/rand"
	"reflect"
)

// flipBitValue flips random bit in the value.
func mutateValue(src *rand.Rand, value any) error {
	data := make([]byte, 0, reflect.TypeOf(value).Size())
	buf := bytes.NewBuffer(data)
	if err := binary.Write(buf, nativeEndian, value); err != nil {
		return err
	}
	flipBit(src, buf.Len(), buf.Bytes())
	return binary.Read(buf, nativeEndian, value)
}

func MutateString(src *rand.Rand, str string, maxSize int) (string, error) {
	value, err := MutateBytes(src, []byte(str), maxSize)
	if err != nil {
		return "", err
	}
	if err := FixUTF8(value, src); err != nil {
		return "", err
	}
	return string(value), nil
}

func MutateBytes(src *rand.Rand, value []byte, maxSize int) ([]byte, error) {
	result := make([]byte, len(value))
	copy(result, value)

	for len(result) > 0 && GetRandomBool(src) {
		index := getRandomRange(src, len(result))
		result = append(result[:index], result[index+1:]...)
	}

	for len(result) < maxSize && GetRandomBool(src) {
		index := getRandomRange(src, len(result)+1)
		result = append(result, byte(getRandomRange(src, 1<<8)))
		result[index], result[len(result)-1] = result[len(result)-1], result[index]
	}

	if !bytes.Equal(result, value) {
		return result, nil
	}

	if len(result) == 0 {
		result = append(result, byte(getRandomRange(src, 1<<8)))
		return result, nil
	}

	flipBit(src, len(result), result)
	return result, nil
}
