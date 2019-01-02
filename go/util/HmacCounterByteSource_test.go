package util

import (
	"testing"
	"github.com/stretchr/testify/assert"
	"io"
	"encoding/hex"
)

func Test_HmacCounterByteSource(t *testing.T) {
	assert := assert.New(t)

	key := ByteSequence(1, 32)

	src := NewHmacCounterByteSource(key, 3)
	reader := &ByteSourceReader{Source: src}

	//read the first 32 bytes
	block := make([]byte, 32)
	n, err := reader.Read(block)
	assert.Equal(32, n)
	assert.Nil(err)
	assert.Equal(HmacSha256(key, []byte{0,0,0,0}), block)
	assert.Equal("2c8463ac51f796043dcd8edc7d3dda424569314980cdd762a562ef88c1718ca0", hex.EncodeToString(block))

	//read 32 more
	n, err = reader.Read(block)
	assert.Equal(32, n)
	assert.Nil(err)
	assert.Equal(HmacSha256(key, []byte{0,0,0,1}), block)
	assert.Equal("3df609df0d17be5e19ba72218136e82546a973b1388c2e7beb95a9184355fe18", hex.EncodeToString(block))

	//final 32
	n, err = reader.Read(block)
	assert.Equal(32, n)
	assert.Nil(err)
	assert.Equal(HmacSha256(key, []byte{0,0,0,2}), block)
	assert.Equal("7b8da86c3ebdd0a2dc5dd679037d18ee079a25d585557790abeb9f4c3f21e46a", hex.EncodeToString(block))

	//one more causes error
	_, err = reader.Source.NextByte()
	assert.True(err == io.EOF)

	//Verify correct 32bit counting
	src.maxCounter = 0xffffffff
	src.counter = 0xABCDEF98
	src.blockOffset = 32
	
	n, err = reader.Read(block)
	assert.Equal(32, n)
	assert.Nil(err)
	assert.Equal(HmacSha256(key, []byte{0xAB,0xCD,0xEF,0x98}), block)
	assert.Equal("5c126654874aef85c6e34130183cf70e36749eae73fa3d095c23063d6086e3af", hex.EncodeToString(block))
}
