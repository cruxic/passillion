/*
Calculate passillion word coordinates from the command line.
*/
package main

import (
	"log"
	"flag"
	"github.com/cruxic/passillion/go/type1"
	"golang.org/x/crypto/ssh/terminal"  //for reading password from the console
	"bufio"
	"fmt"
	"strings"
	"os"
	"syscall"
)


func main() {
	log.SetFlags(0)  //no timestamp

	flagType1 := flag.Bool("1", false, "Use \"Type 1\" algorithm")
	nWords := flag.Int("n", 4, "Output a different number of word coordinates")
	flagCheckword := flag.Bool("checkword", false, "Print the 3 letter \"checkword\" for a given password.")

	flag.Parse()

	if *flagCheckword {
		doCheckword()
	} else if *flagType1 {
		doType1(*nWords)
	} else {
		flag.Usage()
	}
}

func plainPrompt(reader * bufio.Reader, message string, isValid func(string) error) string {
	for {
		fmt.Printf("%s: ", message)
		ans, err := reader.ReadString('\n')
		if err != nil {
			log.Fatal("error reading stdin")
		}

		ans = strings.TrimSpace(ans)

		err = isValid(ans)
		if err == nil {
			return ans
		} else {
			fmt.Fprintf(os.Stderr, "%s\n", err.Error())
			//loop and try again
		}
	}

	return strings.TrimSpace(message)
}

func securePrompt(message string, isValid func(string) error) string {
	for {
		fmt.Printf("%s: ", message)
		rawPass, err := terminal.ReadPassword(int(syscall.Stdin))
		if err != nil {
			log.Fatal("error reading stdin")
		}
		fmt.Println()

		pass := strings.TrimSpace(string(rawPass))

		err = isValid(pass)
		if err == nil {
			return pass
		} else {
			fmt.Fprintf(os.Stderr, "%s\n", err.Error())
			//loop and try again
		}
	}

	return strings.TrimSpace(message)
}

func doType1(nWords int) {
	reader := bufio.NewReader(os.Stdin)

	sitename := plainPrompt(reader, "Sitename", func(s string) error {
		if len(s) == 0 {
			return fmt.Errorf("Sitename cannot be empty")
		} else {
			return nil
		}
	})

	personalization := plainPrompt(reader, "Revsion number, user name, etc (optional)", func(s string) error {
		return nil
	})

	coordPass := securePrompt("Coordinate Password", func(s string) error {
		if len(s) < type1.MinCoordPassLen {
			return fmt.Errorf("Password must be at least %d characters", type1.MinCoordPassLen)
		} else {
			//Verify checkword
			pass, checkword := type1.SplitCheckword(s)
			if type1.IsCorrectCheckword(pass, checkword) {
				//Good!
				return nil
			} else {
				return fmt.Errorf("Typo or missing checkword? Use `passn -checkword` if you forgot your checkword.")
			}
		}
	})

	sitehash, err := type1.CalcSiteHash(coordPass, sitename, personalization)
	if err != nil {
		log.Fatal(err)
	}

	coords, err := type1.GetWordCoordinates(sitehash, nWords)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Word coordinates:\n")
	for _, coord := range coords {
		fmt.Printf("  %s", coord)
	}
	fmt.Println("\n")
	fmt.Println(`Remember:
  1. Beware of Phishing!  Don't log in via email links.
  2. Capitalize the first word.
  3. End with one digit.
  4. No spaces.`)
}

func doCheckword() {
	fmt.Println("The \"checkword\" is 3 letter word which you type after your password to detect\n" +
		"a typo in the preceeding characters. Enter a password now to see the associated\ncheckword.")

	pass := securePrompt("Enter any password", func(s string) error {
		if len(s) == 0 {
			return fmt.Errorf("Cannot be empty.")
		} else {
			return nil			
		}
	})

	checkword := type1.CalcCheckword(pass)
	fmt.Printf("Checkword: %s\n", checkword)
}
