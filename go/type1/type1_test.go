package type1

import (
	"testing"
	"github.com/stretchr/testify/assert"
	"encoding/hex"
	"strings"
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
	all := make([]string, 0, 256)
	for i := 0; i < 256; i += 32 {
		coords, err = GetWordCoordinates(SiteHash(makeSeq(i, 32)), 32)
		assert.NoError(err)
		all = append(all, coords...)
	}

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
