package pkgUtils

import (
	"fmt"
)

type Buffer struct {
	Arr      []byte
	Len      int16
	Head     int16
	LastRead int16
}

func (b *Buffer) Write(data []byte) {

	fmt.Println("data ", string(data))
	fmt.Println("b.Head ", b.Head)
	fmt.Println("b.Len ", b.Len)

	// detect wraparound
	if b.Head+int16(len(data)) > b.Len { // yes wraparound
		fmt.Println("wraparound in callback")
		secondChunkSize := b.Head + int16(len(data)) - b.Len
		firstChunkSize := b.Len - b.Head
		b.Arr = append(b.Arr, data[:firstChunkSize]...)
		copy(b.Arr[:secondChunkSize], data[firstChunkSize:])
	} else { // no wraparaound
		fmt.Println("no wrap in callback")
		b.Arr = append(b.Arr, data...)
	}

	b.Head += int16(len(data))
	b.Head = b.Head % b.Len
	fmt.Println("buffer in write: ", b.Arr)
}

func (b *Buffer) Read(numBytes int16) (data []byte) {
	fmt.Println("numBytes ", numBytes)
	fmt.Println("b.Head ", b.Head)
	fmt.Println("b.Len ", b.Len)

	// detect wraparound; potentially off by 1
	if b.Head+numBytes <= b.Len { // there is no wraparound
		fmt.Println("no wraparound. metadata head: ", b.Head)
		fmt.Println("bytes to read ", numBytes)
		end := b.Head + numBytes
		data = b.Arr[b.Head:end]
	} else { // there is a wraparound
		fmt.Println("wraparound")
		data = b.Arr[b.Head:] // first chunk: head to end of buffer
		diff := b.Head + numBytes - b.Len
		data = append(data, b.Arr[:diff]...) // append second chunk (starting from beginning of buffer)
	}
	b.LastRead += numBytes
	b.LastRead = b.LastRead % b.Len

	fmt.Println("data as bytes: ", data)
	fmt.Printf("Read %d bytes: %s\n", numBytes, string(data))
	return data
}
