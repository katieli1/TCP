package main

import (
	"fmt"
	buf "ip/pkg/buffer"
)

func main() {
	test_basic()
	test_wraparound()
}

func test_basic() {
	b := buf.Buffer{Head: 0, Len: 10, Arr: make([]byte, 0)}
	b.Write([]byte("Hello"))
	fmt.Println("Result ", string(b.Read(3)))

}

func test_wraparound() {
	b := buf.Buffer{Head: 0, Len: 10, Arr: make([]byte, 0)}
	b.Write([]byte("qwertyuiopasdfghjkl"))
	fmt.Println("Result ", string(b.Read(3)))
}
