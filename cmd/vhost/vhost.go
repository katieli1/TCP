package main

import (
	"ip/pkg/lookup"
	"os"
)


func main() {
	fileName := os.Args[2]
	lookup.RegisterRecvHandler(0, lookup.Callback_test)
	lookup.Initialize(fileName)

}
