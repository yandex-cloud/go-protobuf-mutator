// Code point ↔ UTF-8 conversion
// First code point	Last code point	Byte 1	Byte 2	Byte 3	Byte 4
// U+0000	U+007F	0xxxxxxx
// U+0080	U+07FF	110xxxxx	10xxxxxx
// U+0800	U+FFFF	1110xxxx	10xxxxxx	10xxxxxx
// U+10000	[b]U+10FFFF	11110xxx	10xxxxxx	10xxxxxx	10xxxxxx

package mutator

import (
	"bytes"
	"math/rand"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/stretchr/testify/require"
)

func TestFixUTF8(t *testing.T) {
	src := rand.New(rand.NewSource(time.Now().Unix()))
	for run := 0; run < 10000; run++ {
		// get random size of string
		size := src.Intn(8)
		data := make([]byte, size)
		for i := 0; i < len(data); i++ {
			// fill with random bytes
			data[i] = byte(src.Intn(0xFF))
		}

		str := make([]byte, size)
		copy(str, data)

		require.NoError(t, FixUTF8(data, src))
		if utf8.Valid(str) {
			// if data was already a valid utf8 string
			// validate it is not changed
			require.True(t, bytes.Equal(str, data))
		} else {
			// validate fixed data is a valid utf8 string
			require.True(t, utf8.Valid(data))
		}
	}
}
