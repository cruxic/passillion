package type1

import (
	"github.com/cruxic/mbcrypt/go"
	"errors"
	"crypto/sha256"
	"fmt"
	"strings"
)

//32 byte hash
type SiteHash []byte

const MinCoordPassLen = 10

/*
Convert ASCII A-Z to lower case a-z.  It does NOT touch other Unicode characters.
This function is part of the normalization applied to the site name and
personalization text.

This limitation was motivated by the fact that Unicode case folding is non-trival,
(https://www.w3.org/International/wiki/Case_folding), and not available or
 implemented consistently in every programming language.  I favor consistent
 algorithmic output over international support for now.
*/
func ToLowerAZ(s string) string {
	//Since A-Z is < 128 and Go strings are utf8 we can just check
	// the raw byte values instead of decoding the utf8.
	raw := []byte(s)

	s2 := make([]byte, len(raw))
	const delta = byte('a' - 'A')

	for i, b := range raw {
		if b >= 'A' && b <= 'Z' {
			b += delta
		}
		s2[i] = b
	}

	return string(s2)
}

/*
This normalization is applied to the sitename and personalization to ensure
same word coordinates despite CAPSLOCK or extra white spaces.
*/
func NormalizeField(s string) string {
	s = strings.TrimSpace(s)

	s = ToLowerAZ(s)

	//Replace newlines and tabs with single space
	s = strings.Replace(s, "\n", " ", -1)
	s = strings.Replace(s, "\r", " ", -1)
	s = strings.Replace(s, "\t", " ", -1)

	//Replace duplicate white-spaces with a single space.
	for strings.Contains(s, "  ") {
		s = strings.Replace(s, "  ", " ", -1)
	}

	return s
}

/*
This function creates the "salt" used for the mbcrypt KDF.
It is not actually salt because it's not random. This creates the possibility
of rainbow table assisted guessing of the coordinate password.

I believe this to be an acceptable trade-off.  Firstly, the coordinate
password does not invite attack because it requires the adversary to obtain
your physical word list, (which is printed on paper and users are implored to never
digitize it).  A physical compromise means the adversary is targeting you, personally,
as opposed bulk cracking of a leaked database.  It would be foolish of the adversary to
go through the extra computational work of creating a rainbow table to attack a
single target.  Additionally, the precomputed table would not include any specifics
of his target like pet names, street addresses and favorite sports teams.

Secondly, since the "salt" includes the website, the rainbow table would have to be
 built for many websites.  If the advesary choses the top 10 sites, his table takes
 10x longer to build and occupies significantly more storage space.

Finally, the hash is expensive!  4 invokations of bcrypt, each cost 11.  This is
effectively bcrypt 13.  Bcrypt is still one of the most GPU resistant hashes.
*/
func makeSiteId(site, personalization string) []byte {
	s := "passillion-type1\n" + NormalizeField(site) + "\n" + NormalizeField(personalization)
	h := sha256.Sum256([]byte(s))
	return h[0:mbcrypt.BcryptSaltLen]
}

/*
Return a checksum of the given password in the form of a 3 letter English word.
*/
func CalcCheckword(password string) string {
	hash := sha256.Sum256([]byte(password))
	return gCheckwords[int(hash[0])]	
}

/*
Split the string three characters from the end.  Returned checkword
will be empty if string is too short
*/
func SplitCheckword(passwordWithCheckword string) (pass, checkword string) {
	n := len(passwordWithCheckword)
	if n > 3 {
		pass = passwordWithCheckword[0:n-3]
		checkword = passwordWithCheckword[n-3:]
		return
	} else {
		//too short
		pass = passwordWithCheckword
		checkword = ""
		return
	}
}

func IsCorrectCheckword(password, checkword string) bool {
	return CalcCheckword(password) == ToLowerAZ(checkword)
}

/*
Hash the password with the site name using multiple bcrypt threads.
The sitename and personalization parameters will be normalized with NormalizeField() before hashing.
*/
func CalcSiteHash(password, sitename, personalization string) (SiteHash, error) {
	var hash SiteHash

	if len(password) < MinCoordPassLen {
		return hash, fmt.Errorf("password must be at least %d characters", MinCoordPassLen)
	}

	if len(sitename) == 0 {
		return hash, errors.New("sitename cannot be empty")
	}

	siteId := makeSiteId(sitename, personalization)

	//4 bcrypt threads, each cost 11
	h, err := mbcrypt.Hash(4, []byte(password), siteId, 11)
	if err != nil {
		return hash, err
	}

	return SiteHash(h), nil
}

//The twelve column header letters as a string.
const ColumnLetters = "ABCDEFTUVXYZ"

func getColSize(columnIndex int) int {
	//First three columns and very last colum have 20.
	//All others are 22.
	if columnIndex < 3 || columnIndex == 11 {
		return 20
	} else {
		return 22
	}
}

type _ColAndWordNum struct {
	//Column index (0-11). Corresponds to 'ColumnLetters'
	ColumnIndex int

	//word number within the column. Note: word numbers are unique
	//  within the entire quadrant (3 columns).
	WordNumber int
}

/*
Given a word index (0-255) get the column it belongs in (0-11) and
the word number within that column.  Note: word numbers are unique
within the entire quadrant (3 columns).
*/
func getColumnIndexAndWordNumber(wordIndex int) _ColAndWordNum {
	if wordIndex < 0 || wordIndex > 255 {
		panic("wordIndex out of range");
	}

	//For each column...
	k := 0
	numInQuad := 1
	for col := 0; col < 12; col++ {
		//reset numInQuad when starting new quadrant
		if col % 3 == 0 {
			numInQuad = 1
		}

		colSize := getColSize(col)
		k += colSize
		if wordIndex < k {
			k -= colSize
			return _ColAndWordNum{
				ColumnIndex: col,
				WordNumber: numInQuad + (wordIndex - k),
			}
		}

		numInQuad += colSize
	}

	//will never reach here
	panic("assert fail")
}


/*
Given the SiteHash, get word coordinates (eg "C13", "X9", ...).
*/
func GetWordCoordinates(hash SiteHash, nWords int) ([]string, error) {
	if len(hash) != 32 {
		return nil, errors.New("wrong hash length")
	}

	if nWords < 1 || nWords > len(hash) {
		return nil, errors.New("nWords out of range")
	}

	coords := make([]string, nWords)

	for i := 0; i < nWords; i++ {
		wordIndex := int(hash[i])  //0-255
		//Note: no modulo bias since wordIndex is exactly 8 bits.

		cw := getColumnIndexAndWordNumber(wordIndex)

		letter := ColumnLetters[cw.ColumnIndex:cw.ColumnIndex+1]
		coords[i] = fmt.Sprintf("%s%d", letter, cw.WordNumber)
	}

	return coords, nil
}
