package main

import (
	//"fmt"
	"ip/pkg/lookup"
	//"net/netip"
	"os"
)

func main() {
	fileName := os.Args[2]
	lookup.RegisterRecvHandler(0, lookup.Callback_test)
	lookup.RegisterRecvHandler(200, lookup.Callback_RIP)
	lookup.Initialize(fileName)

}
