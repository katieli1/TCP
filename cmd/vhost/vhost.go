package main

import (
	"ip/pkg/lookup"
	"ip/pkg/tcp"
	"os"
)

func main() {
	fileName := os.Args[2]
	lookup.RegisterRecvHandler(0, lookup.Callback_test)
	lookup.RegisterRecvHandler(6, tcp.Callback_TCP)
	tcp.Initialize(fileName)

}
