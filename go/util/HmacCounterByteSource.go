package util

import (
	"hash"
	"crypto/hmac"
	"crypto/sha256"
	"io"
)

/*
A pseudo-random stream bytes obtained from HMAC-SHA256 with a
secret key and an incrementing 32bit counter.
*/
type HmacCounterByteSource struct {
	hm hash.Hash
	
	counter uint32
	maxCounter uint32
	
	//the most recent HMAC output
	block []byte
	blockOffset int
}

/*After maxCounter invokations of HMAC-SHA256 the NextByte() function will return io.EOF.
Each invokation yields 32 bytes.
*/
func NewHmacCounterByteSource(key []byte, maxCounter uint32) *HmacCounterByteSource {
	res := &HmacCounterByteSource{
		hm: hmac.New(sha256.New, key),
		maxCounter: maxCounter,
	}

	res.nextBlock()
	
	return res
}

func (self *HmacCounterByteSource) nextBlock() {
	four := make([]byte, 4)
	four[0] = byte((self.counter >> 24) & 0xFF)
	four[1] = byte((self.counter >> 16) & 0xFF)
	four[2] = byte((self.counter >> 8) & 0xFF)
	four[3] = byte(self.counter & 0xFF)

	//erase previous block
	if self.block != nil {
		Erase(self.block)
	}

	self.hm.Reset()
	self.hm.Write(four)
	self.block = self.hm.Sum(nil)

	self.counter++
	self.blockOffset = 0
}

func (self *HmacCounterByteSource) NextByte() (byte, error) {
	if self.blockOffset >= len(self.block) {
		if self.counter >= self.maxCounter {
			return 0, io.EOF
		}

		self.nextBlock()
	}

	b := self.block[self.blockOffset]
	self.blockOffset++
	return b, nil
}
