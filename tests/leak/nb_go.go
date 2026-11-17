// Go client test (L117): an http GET to the listener and a dial to the
// blackhole with a 1 s timeout. Prints GO-OK when the GET succeeds and
// the dial fails. Args: LISTEN_URL BLACKHOLE_HOSTPORT
package main

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"time"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Println("FAIL: usage nb_go LISTEN_URL BLACKHOLE_HOSTPORT")
		os.Exit(1)
	}
	listenURL := os.Args[1]
	blackhole := os.Args[2]
	client := &http.Client{Timeout: 10 * time.Second}
	res, err := client.Get(listenURL)
	if err != nil {
		fmt.Printf("FAIL: go GET %s: %v\n", listenURL, err)
		os.Exit(1)
	}
	res.Body.Close()
	dialer := &net.Dialer{Timeout: time.Second}
	conn, err := dialer.Dial("tcp", blackhole)
	if err == nil {
		conn.Close()
		fmt.Println("FAIL: go dial to the blackhole succeeded")
		os.Exit(1)
	}
	fmt.Println("GO-OK")
}
