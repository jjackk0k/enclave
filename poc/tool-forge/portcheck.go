// portcheck — a tiny recon utility: reports whether host:port accepts a TCP
// connection. An illustrative security tool, built inside the enclave and
// cross-compiled for Linux and Windows from the same source. Stdlib only.
package main

import (
	"fmt"
	"net"
	"os"
	"time"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Println("usage: portcheck <host> <port>")
		os.Exit(2)
	}
	addr := net.JoinHostPort(os.Args[1], os.Args[2])
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		fmt.Printf("%s: closed/filtered (%v)\n", addr, err)
		os.Exit(1)
	}
	conn.Close()
	fmt.Printf("%s: open\n", addr)
}
