package pkgUtils

import (
	"fmt"
)

type Buffer struct {
	Arr        []byte
	Len        int16
	Head       int16
	LastRead   int16
	WindowSize int16
	Full       bool
}

func (b *Buffer) Write(data []byte) {
	dataLen := int16(len(data))

	// Determine how many bytes we can actually write
	bytesToWrite := dataLen

	// if b.Full {
	// 	return
	// }

	// Write data directly, handling wraparound
	endIndex := b.Head + bytesToWrite
	if endIndex <= b.Len { // No wraparound
		//fmt.Println("no wraparound")
		copy(b.Arr[b.Head:endIndex], data[:bytesToWrite])
	} else { // Wraparound

		firstChunkSize := b.Len - b.Head
		copy(b.Arr[b.Head:], data[:firstChunkSize])
		copy(b.Arr[:endIndex%b.Len], data[firstChunkSize:])
	}

	b.Head = (b.Head + bytesToWrite) % b.Len
	//fmt.Println("updating head to ", b.Head)
	if b.Head == b.LastRead {
		//fmt.Println("setting b.Full to true")
		b.Full = true
	}

	fmt.Println("len(data) ", len(data))
	fmt.Println("updating windowsize from ", b.WindowSize)
	b.WindowSize -= int16(len(data))
	fmt.Println("to ", b.WindowSize)
}

func (b *Buffer) Read(numBytes int16) (data []byte) {
	// detect wraparound; potentially off by 1

	// var maxBytes int16
	// if b.LastRead < b.Head {
	// 	maxBytes = b.Head - b.LastRead
	// } else { // Wraparound case
	// 	maxBytes = b.Len - b.LastRead + b.Head
	// }

	// // Limit numBytes to not exceed maxBytes
	// if numBytes > maxBytes {
	// 	numBytes = maxBytes
	// }

	fmt.Println("last read before if statement ", b.LastRead)
	fmt.Println("head before if statement ", b.Head)
	if b.LastRead == b.Head {
		fmt.Println("last read == head")
		if !b.Full {
			fmt.Printf("Read 0 bytes:\n")
			return make([]byte, 0)
		}
	}

	fmt.Println("b.Len ", b.Len)
	fmt.Println("b.LastRead ", b.LastRead)
	fmt.Println("numBytes ", numBytes)

	if b.LastRead+numBytes <= b.Len { // there is no wraparound
		fmt.Println("no wraparound. metadata head: ", b.Head)

		end := b.LastRead + numBytes
		fmt.Println("end ", end)
		data = b.Arr[b.LastRead:end]
	} else { // there is a wraparound
		fmt.Println("wraparound")
		data = b.Arr[b.LastRead:] // first chunk: head to end of buffer
		diff := b.LastRead + numBytes - b.Len
		fmt.Println("updating windowsize from ", b.WindowSize)
		b.WindowSize = b.Len - diff
		fmt.Println("updating windowsize from ", b.WindowSize)
		data = append(data, b.Arr[:diff]...) // append second chunk (starting from beginning of buffer)
	}
	b.LastRead += numBytes
	b.LastRead = b.LastRead % b.Len
	if b.Head == b.LastRead {
		fmt.Println("setting b.Full to false")
		b.Full = false
	}

	// fmt.Println("data as bytes: ", data)
	// fmt.Printf("Read %d bytes: %s\n", numBytes, string(data))

	// fmt.Println("head pos at end of read: ", b.Head)
	// fmt.Println("lastread pos at end of read: ", b.LastRead)
	fmt.Println("updating windowsize from ", b.WindowSize)
	b.WindowSize += int16(min(int16(len(data)), b.Len))
	fmt.Println("updating windowsize from ", b.WindowSize)
	return data
}

func (b *Buffer) GetLastRead() int16 {
	return b.LastRead
}
