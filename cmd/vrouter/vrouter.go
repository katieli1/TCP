package main

import (
	"fmt"
	"ip/pkg/lookup"
	"os"
)

func callback(msg string) {
	fmt.Println("Received test packet: " + msg)

}
func main() {
	fmt.Println("In main!")
	if len(os.Args) != 2 {
		fmt.Printf("Usage:  %s <configFile>\n", os.Args[0])
		os.Exit(1)
	}
	fileName := os.Args[1]
	lookup.RegisterRecvHandler(0, callback)
	lookup.Initialize(fileName)

}
