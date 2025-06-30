package mutator

import (
	"math/rand"

	"google.golang.org/protobuf/reflect/protoreflect"
)

const defaultMutateWeight = 1000000

type mutateSample struct {
	mutate  func(message protoreflect.Message, field protoreflect.FieldDescriptor) error
	message protoreflect.Message
	field   protoreflect.FieldDescriptor
}

// Algorithm pick one item from the sequence of weighted items.
// https://en.wikipedia.org/wiki/Reservoir_sampling#Algorithm_A-Chao
//
// Example:
//
//	weightedReservoirSampler sampler;
//	for(int i = 0; i < size; i++)
//	  sampler.Pick(weight[i], i);
//	return sampler.Value();
func newWeightedReservoirSampler(src *rand.Rand) *weightedReservoirSampler {
	return &weightedReservoirSampler{
		src: src,
	}
}

type weightedReservoirSampler struct {
	TotalWeight int
	src         *rand.Rand
	selected    *mutateSample
}

func (w *weightedReservoirSampler) Value() *mutateSample {
	return w.selected
}

func (w *weightedReservoirSampler) pick(weight int) bool {
	if weight == 0 {
		return false
	}

	w.TotalWeight += weight
	return weight == w.TotalWeight || getRandomRange(w.src, w.TotalWeight) <= weight
}

func (w *weightedReservoirSampler) Try(value mutateSample) {
	if w.pick(defaultMutateWeight) {
		w.selected = &value
	}
}
