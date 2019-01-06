package main

import "net/http"
import "path/filepath"
import "os"
import "log"
import "fmt"

func main() {
	cwd, err := os.Getwd()
	if err != nil {
		log.Fatal(err)
	}
	
	thisDir, err := filepath.Abs(cwd)
	if err != nil {
		log.Fatal(err)
	}

	listenOn := ":7777"
	fmt.Println("Preparing to listen on", listenOn)
	
    panic(http.ListenAndServe(listenOn, http.FileServer(http.Dir(thisDir))))
}
