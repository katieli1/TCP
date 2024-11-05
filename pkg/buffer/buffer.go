package pkgUtils

import (
	"fmt"
)

type Buffer struct {
	Arr      []byte
	Len      int16
	Head     int16
	LastRead int16
	WindowSize int16
}

func (b *Buffer) Write(data []byte) {
	dataLen := int16(len(data))

	// Determine how many bytes we can actually write
	bytesToWrite := dataLen

	// Write data directly, handling wraparound
	endIndex := b.Head + bytesToWrite
	if endIndex <= b.Len { // No wraparound
		copy(b.Arr[b.Head:endIndex], data[:bytesToWrite])
	} else { // Wraparound
		firstChunkSize := b.Len - b.Head
		copy(b.Arr[b.Head:], data[:firstChunkSize])
		copy(b.Arr[:endIndex%b.Len], data[firstChunkSize:])
	}

	b.Head = (b.Head + bytesToWrite) % b.Len
}

func (b *Buffer) Read(numBytes int16) (data []byte) {
	//TODO: this only solves one wrap arround fix it (?)
	// detect wraparound; potentially off by 1

	var maxBytes int16
	if b.LastRead < b.Head {
		maxBytes = b.Head - b.LastRead
	} else { // Wraparound case
		maxBytes = b.Len - b.LastRead + b.Head
	}
	
	// Limit numBytes to not exceed maxBytes
	if numBytes > maxBytes {
		numBytes = maxBytes
	}

	if b.LastRead+numBytes <= b.Len { // there is no wraparound
		// fmt.Println("no wraparound. metadata head: ", b.Head)
		end := b.LastRead + numBytes
		data = b.Arr[b.LastRead:end]
	} else { // there is a wraparound
		data = b.Arr[b.LastRead:] // first chunk: head to end of buffer
		diff := b.LastRead + numBytes - b.Len
		data = append(data, b.Arr[:diff]...) // append second chunk (starting from beginning of buffer)
	}
	b.LastRead += numBytes
	b.LastRead = b.LastRead % b.Len

	fmt.Println("data as bytes: ", data)
	fmt.Printf("Read %d bytes: %s\n", numBytes, string(data))
	return data
}

func (b *Buffer) GetLastRead() int16 {
	return b.LastRead
}
