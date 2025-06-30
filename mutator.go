package mutator

import (
	"fmt"
	"math/rand"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

type mutator struct {
	random           *rand.Rand
	sizeIncreaseHint int
}

// NewMutator creates new struct to mutate ProtoMessage
// for the same seed mutations must return the same result
// sizeIncreaseHint is the maximum size to increase proto message
func New(seed int64, sizeIncreaseHint int) Mutator {
	return &mutator{
		random:           rand.New(rand.NewSource(seed)),
		sizeIncreaseHint: sizeIncreaseHint,
	}
}

func (m *mutator) MutateProto(msg proto.Message) error {
	return m.mutateMessage(msg.ProtoReflect())
}

func (m *mutator) mutateMessage(message protoreflect.Message) error {
	msgDesc := message.Descriptor()
	fieldsDesc := msgDesc.Fields()

	if fieldsDesc.Len() == 0 {
		// nothing to mutate
		return nil
	}

	sampler := newWeightedReservoirSampler(m.random)
	for ind := 0; ind < fieldsDesc.Len(); ind++ {
		fieldDesc := fieldsDesc.Get(ind)

		if message.Has(fieldDesc) && GetRandomBoolN(m.random, 20) {
			// try to clear field
			sampler.Try(mutateSample{m.clearField, message, fieldDesc})
		}

		switch {
		case fieldDesc.ContainingOneof() != nil:
			sampler.Try(mutateSample{m.mutateOneOf, message, fieldDesc})

		case fieldDesc.IsMap():
			sampler.Try(mutateSample{m.addMap, message, fieldDesc})
			sampler.Try(mutateSample{m.mutateMap, message, fieldDesc})
			sampler.Try(mutateSample{m.clearMap, message, fieldDesc})

		case fieldDesc.IsList():
			sampler.Try(mutateSample{m.addList, message, fieldDesc})
			sampler.Try(mutateSample{m.mutateList, message, fieldDesc})
			sampler.Try(mutateSample{m.clearList, message, fieldDesc})

		case fieldDesc.Kind() == protoreflect.MessageKind:
			sampler.Try(mutateSample{m.mutateMessageField, message, fieldDesc})

		default:
			sampler.Try(mutateSample{m.mutateField, message, fieldDesc})
		}
	}

	mutation := sampler.Value()
	return mutation.mutate(mutation.message, mutation.field)
}

func (m *mutator) mutateMessageField(message protoreflect.Message, field protoreflect.FieldDescriptor) error {
	if field.Message() == nil {
		return fmt.Errorf("Invalid field kind: expected message, got %v", field.Kind())
	}

	// should take mutable message to mutate it
	mutable := message.Mutable(field).Message()
	return m.mutateMessage(mutable)
}

func (m *mutator) clearField(message protoreflect.Message, field protoreflect.FieldDescriptor) error {
	message.Clear(field)
	return nil
}

func (m *mutator) mutateOneOf(message protoreflect.Message, fieldDesc protoreflect.FieldDescriptor) error {
	oneOf := fieldDesc.ContainingOneof()
	index := getRandomRange(m.random, oneOf.Fields().Len())
	field := oneOf.Fields().Get(index)

	return m.mutateField(message, field)
}

func (m *mutator) mutateMap(message protoreflect.Message, field protoreflect.FieldDescriptor) error {
	if !field.IsMap() {
		return fmt.Errorf("Invalid field kind: expected map, got %v", field.Kind())
	}
	mapDesc := message.Get(field).Map()

	if mapDesc.Len() == 0 {
		// could not mutate empty map
		// create new field
		return m.addMap(message, field)
	}

	entries := make([]struct {
		Key   protoreflect.MapKey
		Value protoreflect.Value
	}, 0, mapDesc.Len())
	mapDesc.Range(func(mk protoreflect.MapKey, v protoreflect.Value) bool {
		entries = append(entries, struct {
			Key   protoreflect.MapKey
			Value protoreflect.Value
		}{
			Key:   mk,
			Value: v,
		})
		return true
	})

	index := getRandomRange(m.random, len(entries))
	entry := entries[index]

	mutated, err := m.mutateProtoValue(field.MapValue(), entry.Value)
	if err != nil {
		return err
	}
	mapDesc.Set(entry.Key, mutated)

	return nil
}

func (m *mutator) addMap(message protoreflect.Message, field protoreflect.FieldDescriptor) error {
	if !field.IsMap() {
		return fmt.Errorf("Invalid field kind: expected map, got %v", field.Kind())
	}
	mapDesc := message.Mutable(field).Map()

	keyValue := field.MapKey().Default()
	for i := 0; i < 10; i++ {
		var err error
		keyValue, err = m.mutateProtoValue(field.MapKey(), keyValue)
		if err != nil {
			return err
		}
		if !mapDesc.Has(keyValue.MapKey()) {
			break
		}
	}
	if mapDesc.Has(keyValue.MapKey()) {
		// could not create new field
		// mutate existing one
		return m.mutateMap(message, field)
	}

	// NewValue creates default value
	// try to mutate it
	mapValue := mapDesc.NewValue()
	mapValue, err := m.mutateProtoValue(field.MapValue(), mapValue)
	if err != nil {
		return err
	}

	mapDesc.Set(keyValue.MapKey(), mapValue)
	return nil
}

func (m *mutator) clearMap(message protoreflect.Message, field protoreflect.FieldDescriptor) error {
	if !field.IsMap() {
		return fmt.Errorf("Invalid field kind: expected map, got %v", field.Kind())
	}
	mapDesc := message.Get(field).Map()

	if mapDesc.Len() == 0 {
		// could not delete element from empty map
		// create new field
		return m.addMap(message, field)
	}

	entries := make([]protoreflect.MapKey, 0, mapDesc.Len())
	mapDesc.Range(func(mk protoreflect.MapKey, v protoreflect.Value) bool {
		entries = append(entries, mk)
		return true
	})

	// remove random element from map
	index := getRandomRange(m.random, len(entries))
	mapDesc.Clear(entries[index])
	return nil
}

func (m *mutator) mutateList(message protoreflect.Message, field protoreflect.FieldDescriptor) error {
	if !field.IsList() {
		return fmt.Errorf("Invalid field kind: expected list, got %v", field.Kind())
	}
	list := message.Mutable(field).List()
	if list.Len() == 0 {
		// could not mutate empty list
		// add new element
		return m.addList(message, field)
	}
	index := getRandomRange(m.random, list.Len())
	value := list.Get(index)
	mutated, err := m.mutateProtoValue(field, value)
	if err != nil {
		return err
	}
	list.Set(index, mutated)
	return nil
}

func (m *mutator) clearList(message protoreflect.Message, field protoreflect.FieldDescriptor) error {
	if !field.IsList() {
		return fmt.Errorf("Invalid field kind: expected list, got %v", field.Kind())
	}
	list := message.Mutable(field).List()
	if list.Len() == 0 {
		// could not clear empty list
		// add new element
		return m.addList(message, field)
	}

	// remove random index from list
	index := getRandomRange(m.random, list.Len())
	last := list.Get(list.Len() - 1)
	list.Set(index, last)
	list.Truncate(list.Len() - 1)
	return nil
}

func (m *mutator) addList(message protoreflect.Message, field protoreflect.FieldDescriptor) error {
	if !field.IsList() {
		return fmt.Errorf("Invalid field kind: expected list, got %v", field.Kind())
	}

	list := message.Mutable(field).List()
	value := list.NewElement()
	value, err := m.mutateProtoValue(field, value)
	if err != nil {
		return err
	}

	list.Append(value)
	return nil
}

func (m *mutator) mutateField(message protoreflect.Message, field protoreflect.FieldDescriptor) error {
	kind := field.Kind()

	switch {
	case field.IsMap():
		return m.mutateMap(message, field)

	case field.IsList():
		return m.mutateList(message, field)
	case kind == protoreflect.MessageKind:
		return m.mutateMessageField(message, field)
	default:
		mutated, err := m.mutateProtoValue(field, message.Get(field))
		if err != nil {
			return err
		}
		message.Set(field, mutated)
	}

	return nil
}

func (m *mutator) mutateProtoValue(field protoreflect.FieldDescriptor, protoValue protoreflect.Value) (protoreflect.Value, error) {
	kind := field.Kind()
	switch kind {
	case protoreflect.StringKind:
		value := protoValue.String()

		// increase possible max size
		mutated, err := MutateString(m.random, value, len(value)+m.sizeIncreaseHint)
		if err != nil {
			return protoValue, err
		}
		return protoreflect.ValueOf(mutated), nil
	case protoreflect.BoolKind:
		value := protoValue.Bool()
		err := MutateBool(m.random, &value)
		if err != nil {
			return protoValue, err
		}
		return protoreflect.ValueOf(value), nil
	case protoreflect.Int32Kind, protoreflect.Int64Kind:
		value := protoValue.Int()
		err := MutateInt64(m.random, &value)
		if err != nil {
			return protoValue, err
		}
		return protoreflect.ValueOf(value), nil
	case protoreflect.Uint32Kind, protoreflect.Uint64Kind:
		value := protoValue.Uint()
		err := MutateUint64(m.random, &value)
		if err != nil {
			return protoValue, err
		}
		return protoreflect.ValueOf(value), nil
	case protoreflect.FloatKind, protoreflect.DoubleKind:
		value := protoValue.Float()
		err := MutateFloat64(m.random, &value)
		if err != nil {
			return protoValue, err
		}
		return protoreflect.ValueOf(value), nil
	case protoreflect.BytesKind:
		value := protoValue.Bytes()
		mutated, err := MutateBytes(m.random, value, len(value))
		if err != nil {
			return protoValue, err
		}
		return protoreflect.ValueOf(mutated), nil
	case protoreflect.MessageKind:
		value := protoValue.Message()
		if err := m.mutateMessage(value); err != nil {
			return protoValue, err
		}
		return protoreflect.ValueOf(value), nil
	case protoreflect.EnumKind:
		return protoreflect.ValueOf(m.getRandomEnum(field.Enum())), nil
	}

	return protoValue, fmt.Errorf("Unexpected field kind: %v", kind)
}

func (m *mutator) getRandomEnum(enumDescriptor protoreflect.EnumDescriptor) protoreflect.EnumNumber {
	randomIndex := m.random.Intn(enumDescriptor.Values().Len())
	return enumDescriptor.Values().Get(randomIndex).Number()
}

func (m *mutator) MutateBool(value *bool) error {
	return MutateBool(m.random, value)
}
func (m *mutator) MutateFloat64(value *float64) error {
	return MutateFloat64(m.random, value)
}
func (m *mutator) MutateFloat32(value *float32) error {
	return MutateFloat32(m.random, value)
}
func (m *mutator) MutateUint32(value *uint32) error {
	return MutateUint32(m.random, value)
}
func (m *mutator) MutateUint64(value *uint64) error {
	return MutateUint64(m.random, value)
}
func (m *mutator) MutateInt32(value *int32) error {
	return MutateInt32(m.random, value)
}
func (m *mutator) MutateInt64(value *int64) error {
	return MutateInt64(m.random, value)
}

func (m *mutator) MutateString(str string, maxSize int) (string, error) {
	return MutateString(m.random, str, maxSize)
}

func (m *mutator) MutateBytes(value []byte, maxSize int) ([]byte, error) {
	return MutateBytes(m.random, value, maxSize)
}
