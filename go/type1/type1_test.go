package type1

import (
	"testing"
	"github.com/stretchr/testify/assert"
	"encoding/hex"
	"strings"
	"crypto/sha256"
)

func Test_ToLowerAZ(t *testing.T) {
	assert := assert.New(t)

	s := "123456789-abcdefghijklmnopqrstuvwxyz_ABCDEFGHIJKLMNOPQRSTUVWXYZ=~!@#$%^&*()"
	s2 := ToLowerAZ(s)
	assert.Equal("123456789-abcdefghijklmnopqrstuvwxyz_abcdefghijklmnopqrstuvwxyz=~!@#$%^&*()", s2)

	//Characters in other languages are left alone.
	s = "Uppercase Greek Gamma: Γ. Lowercase Gamma: ᵞ."
	s2 = ToLowerAZ(s)
	assert.Equal("uppercase greek gamma: Γ. lowercase gamma: ᵞ.", s2)
}

func Test_NormalizeField(t *testing.T) {
	assert := assert.New(t)

	assert.Equal("", NormalizeField(""))
	assert.Equal("abc", NormalizeField("abc"))
	assert.Equal("ab c", NormalizeField(" \r\n\tAb     C\t\n\r"))
}

func Test_checkwords(t *testing.T) {
	assert := assert.New(t)

	//Sanity: all words are unique and 3 letters.
	sha := sha256.New()
	assert.Equal(256, len(gCheckwords))
	m := make(map[string]bool)
	for _, word := range gCheckwords {
		assert.Equal(3, len(word))
		_, already := m[word]
		assert.False(already)
		m[word] = true
		sha.Write([]byte(word))
	}
	chk := sha.Sum(nil)
	assert.Equal("eb4388f6735a7778a49a8c2cefeaa429f1cadd2bb6a9dd0e777f9e21f07bbc9f", hex.EncodeToString(chk[:]))
	//other implementations can use above hash to verify the word list
}

func Test_CalcCheckword(t *testing.T) {
	assert := assert.New(t)

	assert.Equal("pet", CalcCheckword("Hello World"))
	assert.Equal("log", CalcCheckword("Hello Worlf"))

	assert.True(IsCorrectCheckword("Hello World", "pEt"))  //case insensitive
	assert.True(IsCorrectCheckword("Hello Worlf", "log"))
}

func Test_SplitCheckword(t *testing.T) {
	assert := assert.New(t)

	a, b := SplitCheckword("Hello Worldabc")
	assert.Equal("Hello World", a)
	assert.Equal("abc", b)

	a, b = SplitCheckword(" \tHello World \t  abc \t\n")
	assert.Equal("Hello World", a)
	assert.Equal("abc", b)

	a, b = SplitCheckword("Hello World ab")
	assert.Equal("Hello World ab", a)
	assert.Equal("", b)

	a, b = SplitCheckword("Hi")
	assert.Equal("Hi", a)
	assert.Equal("", b)
}

func Test_CalcSiteHash(t *testing.T) {
	assert := assert.New(t)

	siteha, err := CalcSiteHash("Super Secret", "example.com", "a")
	assert.NoError(err)
	assert.Equal("0d7d37b83abbf8e0ff1cd2e2e943c25207f13040167ce68a672e7eb1c9ca15a3", hex.EncodeToString([]byte(siteha)))

	//vary sitename
	siteha, err = CalcSiteHash("Super Secret", "examplf.com", "a")
	assert.NoError(err)
	assert.Equal("acd8aa32fcd0fd7d4d924d2687d5cbf38ca9ae7174d6dddeb2cb2a79a1c6ac13", hex.EncodeToString([]byte(siteha)))

	//vary password
	siteha, err = CalcSiteHash("Super Secreu", "example.com", "a")
	assert.NoError(err)
	assert.Equal("a6f4ef6b89910ffa0eb0c2e5385dc507197a828fb02ec1f04106618a16954f09", hex.EncodeToString([]byte(siteha)))

	//vary personalization
	siteha, err = CalcSiteHash("Super Secret", "example.com", "b")
	assert.NoError(err)
	assert.Equal("b8e3f9874f9237d7913149929b529158e04686b1cd43d3c5aee5598081635eb8", hex.EncodeToString([]byte(siteha)))

	//sitename and personalization were normalized
	siteha, err = CalcSiteHash("Super Secret", " eXamplE.cOm", " A\n")
	assert.NoError(err)
	assert.Equal("0d7d37b83abbf8e0ff1cd2e2e943c25207f13040167ce68a672e7eb1c9ca15a3", hex.EncodeToString([]byte(siteha)))
}

func makeSeq(start, count int) []byte {
	seq := make([]byte, count)
	for i := 0; i < count; i++ {
		seq[i] = byte(start + i)
	}
	return seq
}


func Test_GetWordCoordinates(t *testing.T) {
	assert := assert.New(t)

	//first 4
	coords, err := GetWordCoordinates(SiteHash(makeSeq(0, 32)), 4)
	assert.NoError(err)
	assert.Equal(4, len(coords))
	s := strings.Join(coords, " ")
	assert.Equal("A1 A2 A3 A4", s)

	//Generate all 256 possible coordinates
	sha := sha256.New()
	all := make([]string, 0, 256)
	for i := 0; i < 256; i += 32 {
		coords, err = GetWordCoordinates(SiteHash(makeSeq(i, 32)), 32)
		assert.NoError(err)
		all = append(all, coords...)
		sha.Write([]byte(strings.Join(coords, " ")))
	}

	h := sha.Sum(nil)
	assert.Equal("09c017822998970604a28fe870753b90567f5b4731626d0fc7ca9137f2867b85", hex.EncodeToString(h))
	//Implementations in other languages can use the above hash to verify all coordinates

	//Spot check first and last of every column

	assert.Equal("A1", all[0])
	assert.Equal("A20", all[19])
	assert.Equal("B21", all[20])
	assert.Equal("B40", all[39])
	assert.Equal("C41", all[40])
	assert.Equal("C60", all[59])

	assert.Equal("D1", all[60])
	assert.Equal("D22", all[81])
	assert.Equal("E23", all[82])
	assert.Equal("E44", all[103])
	assert.Equal("F45", all[104])
	assert.Equal("F66", all[125])

	assert.Equal("T1", all[126])
	assert.Equal("T22", all[147])
	assert.Equal("U23", all[148])
	assert.Equal("U44", all[169])
	assert.Equal("V45", all[170])
	assert.Equal("V66", all[191])

	assert.Equal("X1", all[192])
	assert.Equal("X22", all[213])
	assert.Equal("Y23", all[214])
	assert.Equal("Y44", all[235])
	assert.Equal("Z45", all[236])
	assert.Equal("Z64", all[255])
}
