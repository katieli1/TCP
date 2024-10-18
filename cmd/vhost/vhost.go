package main

import (
	"fmt"
	"ip/pkg/lookup"
	"net/netip"
	"os"
)

func callback_test(msg string, nextHop netip.Addr) {
	fmt.Println("Received test packet: " + msg)
}
func main() {
	// if len(os.Args) != 3 {
	// 	fmt.Printf("Usage:  %s --config <configFile>\n", os.Args[0])
	// 	os.Exit(1)
	// }
	fileName := os.Args[2]
	lookup.RegisterRecvHandler(0, callback_test)
	lookup.Initialize(fileName)

}
