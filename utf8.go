// Code point ↔ UTF-8 conversion
// First code point	Last code point	Byte 1	Byte 2	Byte 3	Byte 4
// U+0000	U+007F	0xxxxxxx
// U+0080	U+07FF	110xxxxx	10xxxxxx
// U+0800	U+FFFF	1110xxxx	10xxxxxx	10xxxxxx
// U+10000	[b]U+10FFFF	11110xxx	10xxxxxx	10xxxxxx	10xxxxxx

package mutator

import (
	"errors"
	"math/rand"
	"unicode/utf8"
)

// FixUTF8 mutates []byte to a valid utf sequence
// does nothing if it is already valid
func FixUTF8(data []byte, src *rand.Rand) error {
	if len(data) == 0 {
		return nil
	}
	for begin := 0; begin < len(data); {
		var err error
		begin, err = fixRune(data, begin, len(data), src)
		if err != nil {
			return err
		}
	}

	return nil
}

func fixRune(data []byte, begin, end int, src *rand.Rand) (int, error) {
	start := begin

	// take minimum from 4 bytes and len of data
	end = min(end, begin+4)

	// decode rune
	code := int32(data[begin])
	begin++

	// while data[b] is a common byte 10xxxxxx increase b
	// and decode rest of rune
	for ; begin < end && (data[begin]&0xC0) == 0x80; begin++ {
		// shift mask
		// c <- 10xxxxxx add last 6 bits
		code = (code << 6) + int32((data[begin] & 0b111111))
	}

	// size of rune in bytes
	size := begin - start
	switch size {
	case 1:
		// for utf8 like 0xxxxxxx
		// mask 0111 1111
		code &= 0x7F
		utf8.EncodeRune(data[start:start+size], code)
	case 2:
		// for utf8 like (110x xxxx 10xx xxxx)
		code &= 0x7FF
		if code < 0x80 {
			// fix rune to be in range from 0x80 to 0x7FF
			code = 0x80 + src.Int31n(0x7FF-0x80)
		}
		utf8.EncodeRune(data[start:start+size], code)

	case 3:
		// for utf8 like (1110xxxx 10xxxxxx 10xxxxxx)
		// mask 0000 1111 1111 1111
		code &= 0xFFFF

		// [0xD800, 0xE000) are reserved for UTF-16 surrogate halves.
		if code < 0x800 || (code >= 0xD800 && code < 0xE000) {
			halves := int32(0xE000 - 0xD800)
			code = 0x800 + src.Int31n(0xFFFF-halves-0x800)
			if code >= 0xD800 {
				code += halves
			}
		}
		utf8.EncodeRune(data[start:start+size], code)
	case 4:
		// for utf8 like (11110xxx 10xxxxxx 10xxxxxx 10xxxxxx)
		// mask (1 1111 1111 1111 1111 1111)
		code &= 0x1FFFFF

		// fix rune to be in range from 0x10000 to 0x10FFFF
		if code < 0x10000 || code > 0x10FFFF {
			code = 0x10000 + src.Int31n(0x10FFFF-0x10000)
		}
		utf8.EncodeRune(data[start:start+size], code)
	default:
		return 0, errors.New("Unexpected size of UTF-8 sequence")
	}
	return begin, nil
}
