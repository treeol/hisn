// Real-network step (L118): http.Get(URL) through the open-mode
// interception. Arg: URL. Prints one line, GO-REAL-OK or FAIL:.
package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"time"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Println("FAIL: go http.Get: usage: nb_real URL")
		os.Exit(1)
	}
	url := os.Args[1]
	client := &http.Client{Timeout: 30 * time.Second}
	res, err := client.Get(url)
	if err != nil {
		fmt.Printf("FAIL: go http.Get(%s): %v\n", url, err)
		os.Exit(1)
	}
	io.Copy(io.Discard, res.Body)
	res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 400 {
		fmt.Printf("FAIL: go http.Get(%s): status %d\n", url, res.StatusCode)
		os.Exit(1)
	}
	fmt.Printf("GO-REAL-OK http.Get(%s) status %d, %s\n", url, res.StatusCode,
		runtime.Version())
}
