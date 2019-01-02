/**Utility functions needed by calcpass.*/
package util

import (
	"io"
	"sort"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
)

/**Request a single byte at a time from some abstract source.*/
type ByteSource interface {
	NextByte() (byte, error)
}

/**Implement ByteSource using a fixed-length slice of bytes.
It returns io.EOF once all bytes have been consumed.
*/
type FixedByteSource struct {
	//The bytes
	Bytes []byte
	
	//Index of the next byte which will be returned
	Index int
}

//Convert a ByteSource to a Reader
type ByteSourceReader struct {
	Source ByteSource
}

func (self *ByteSourceReader) Read(dest []byte) (int, error) {
	var n int
	var err error
	var b byte
	for n = 0; n < len(dest); n++ {
		b, err = self.Source.NextByte()
		if err != nil {
			break
		}

		dest[n] = b
	}

	return n, err
}

func (self *FixedByteSource) NextByte() (byte, error) {
	if self.Index >= len(self.Bytes) {
		return 0, io.EOF
	}
	
	v := self.Bytes[self.Index]
	self.Index++
	
	return v, nil
}

func HmacSha256(key, message []byte) []byte {
	hm := hmac.New(sha256.New, key)
	hm.Write(message)
	hash := hm.Sum(nil)
	hm.Reset() //erase what we can - alas the key has already been copied
	return hash
}

/**Create a random integer from [0, n) where n is <= 256.
This function returns uniformly distributed numbers (no modulo bias).

I am not using math/rand because Intn() consumes bits too quickly (64 at a time).

Returns error if the random source is exhausted or n exceeds 256.
*/
func UnbiasedSmallInt(source ByteSource, n int) (int, error) {
	//Solution from:
	//  https://zuttobenkyou.wordpress.com/2012/10/18/generating-random-numbers-without-modulo-bias/

	var err error
	var b byte
	var r, limit int
	const randmax = 255
	
	if n <= 0 || n > (randmax + 1) {
		return -1, errors.New("UnbiasedSmallInt: n out of range");
	}
	
	limit = randmax - ((randmax+1) % n)
	
	for {
		b, err = source.NextByte()
		if err != nil {
			return -1, err
		}

		r = int(b)
		if r <= limit {
			return r % n, nil
		}
	}
}

/**Fill given slice with zeros.*/
func Erase(sensitive []byte) {
	for i := range sensitive {
		sensitive[i] = 0
	}
}

type shuffleHelper struct {
	rand []int
	array []byte
}

func (self *shuffleHelper) Len() int {
	return len(self.array)
}

func (self *shuffleHelper) Less(i, j int) bool {
	return self.rand[i] < self.rand[j]
}

func (self *shuffleHelper) Swap(i, j int) {
	self.array[i], self.array[j] = self.array[j], self.array[i]
	self.rand[i], self.rand[j] = self.rand[j], self.rand[i]	
}

func SecureShuffleBytes(array []byte, rng ByteSource) error {
	n := len(array)
	if n > 0x7fff {
		return errors.New("SecureShuffleBytes: array too large")
	}

	sh := shuffleHelper{
		rand: make([]int, n),
		array: array,
	}

	//Create a random integer for every element of the array.
	//We must avoid duplicates to ensure predictable sorting.
	var r int
	var err error
	var b1, b2 byte
	used := make(map[int]bool)

	for i := range array {
		for {
			b1, err = rng.NextByte()
			if err != nil {
				return err
			}
			
			b2, err = rng.NextByte()
			if err != nil {
				return err
			}

			//combine 16bits
			r = (int(b1) << 8) | int(b2)

			if !used[r] {
				used[r] = true
				sh.rand[i] = r
				break
			}
		}
	}

	sort.Sort(&sh)

	return nil
}

/**Create an array of increasing byte values.*/
func ByteSequence(start byte, count int) []byte {
	res := make([]byte, count)
	for i := 0; i < count; i++ {
		res[i] = start + byte(i)
	}

	return res
}

type BitReader struct {
	source io.Reader
	currentByte uint32
	//7,6,5,4,3,2,1,0. -1 means currentByte is exahusted
	nextBitPos int
}

func NewBitReader(source io.Reader) *BitReader {
	return &BitReader{
		source: source,
		nextBitPos: -1,
	}
}

/*Read up to 32bits from the source.  When the source Reader returns io.EOF
this function adds in zeros until the requested number of bits is achieved and
then returns io.EOF.  Other errors from the source reader return 0.
*/
func (br *BitReader) ReadBits(nBits int) (uint32, error) {
	var res uint32

	if nBits <= 0 || nBits > 32 {
		return 0, errors.New("ReadBits: nBits must be 1-32")
	}

	one := []byte{0}
	var err error
	
	for nBits > 0 {
		//Read another byte if necessary
		if br.nextBitPos < 0 {
			_, err = br.source.Read(one)
			if err != nil {
				if err == io.EOF {
					//pad with zeros
					res <<= uint32(nBits)
				} else {			
					res = 0
				}

				return res, err
			}

			br.nextBitPos = 7
			br.currentByte = uint32(one[0])
		}

		//avoid if statements due to possible timing attack
		res <<= 1
		res |= (br.currentByte >> uint32(br.nextBitPos)) & 0x01
		br.nextBitPos--
		nBits--
	}

	return res, nil
}


