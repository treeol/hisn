// Go client case (L117). Args: LISTENER_URL BLACKHOLE_HOSTPORT
//
// A net/http GET to the listener must return 200 with the expected
// body, and a dial to the blackhole with a 1 s timeout must fail with a
// timeout after about 1 s (not at once, and not after the supervisor's
// 30 s deadline). Prints one line, GO-OK or FAIL:.
package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"runtime"
	"time"
)

func fail(format string, args ...any) {
	fmt.Printf("FAIL: go client: "+format+"\n", args...)
	os.Exit(1)
}

func main() {
	if len(os.Args) != 3 {
		fail("usage: nb_go LISTENER_URL BLACKHOLE_HOSTPORT")
	}
	listenerURL, blackhole := os.Args[1], os.Args[2]

	client := &http.Client{Timeout: 10 * time.Second}
	res, err := client.Get(listenerURL)
	if err != nil {
		fail("GET %s: %v", listenerURL, err)
	}
	body, err := io.ReadAll(res.Body)
	res.Body.Close()
	if err != nil {
		fail("GET %s: reading the body: %v", listenerURL, err)
	}
	if res.StatusCode != 200 || string(body) != "HERMETIC-OK" {
		fail("GET %s: status %d body %q", listenerURL, res.StatusCode, body)
	}

	dialer := &net.Dialer{Timeout: time.Second}
	start := time.Now()
	conn, err := dialer.Dial("tcp", blackhole)
	took := time.Since(start)
	if err == nil {
		conn.Close()
		fail("dial %s succeeded", blackhole)
	}
	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		fail("dial %s: %v after %v, want a timeout", blackhole, err, took)
	}
	if took < 900*time.Millisecond || took > 3*time.Second {
		fail("dial %s timed out after %v, want about 1 s", blackhole, took)
	}
	fmt.Printf("GO-OK GET %s = %d %s, dial %s timed out after %.2f s, %s\n",
		listenerURL, res.StatusCode, body, blackhole, took.Seconds(),
		runtime.Version())
}
