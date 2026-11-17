// Real-network step (L118): Go http.Get("https://github.com") through the
// open-mode interception. Arg: URL
package main

import (
	"fmt"
	"net/http"
	"os"
	"time"
)

func main() {
	url := os.Args[1]
	client := &http.Client{Timeout: 30 * time.Second}
	res, err := client.Get(url)
	if err != nil {
		fmt.Printf("FAIL: go GET %s: %v\n", url, err)
		os.Exit(1)
	}
	res.Body.Close()
	if res.StatusCode >= 200 && res.StatusCode < 400 {
		fmt.Printf("GO-REAL-OK %d\n", res.StatusCode)
		return
	}
	fmt.Printf("FAIL: go GET status %d\n", res.StatusCode)
	os.Exit(1)
}
