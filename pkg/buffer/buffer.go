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
	//fmt.Println("b.Arr before write ", b.Arr)
	// Write data directly, handling wraparound
	endIndex := b.Head + bytesToWrite
	if endIndex <= b.Len { // No wraparound
		//fmt.Println("no wraparound")
		copy(b.Arr[b.Head:endIndex], data[:bytesToWrite])
	} else { // Wraparound

		firstChunkSize := b.Len - b.Head
		copy(b.Arr[b.Head:], data[:firstChunkSize])
		fmt.Println("first chunk ", data[:firstChunkSize])
		fmt.Println("end of arr ", b.Arr[b.Head:])
		copy(b.Arr[:endIndex%b.Len], data[firstChunkSize:])
		fmt.Println("second chunk ", data[firstChunkSize:])
		fmt.Println("start of arr ", b.Arr[:endIndex%b.Len])
	}
	//fmt.Println("b.Arr after write ", b.Arr)
	fmt.Println("head before update, ", b.Head)
	b.Head = (b.Head + bytesToWrite) % b.Len

	//fmt.Println("updating head to ", b.Head)
	if b.Head == b.LastRead {
		//fmt.Println("setting b.Full to true")
		b.Full = true
	}

	// fmt.Println("len(data) ", len(data))
	// fmt.Println("updating windowsize from ", b.WindowSize)
	//fmt.Println("windowsize before updating in write: ", b.WindowSize)
	b.WindowSize -= int16(len(data))
	//fmt.Println("windowsize before updating in write: ", b.WindowSize)
	// fmt.Println("to ", b.WindowSize)
}

func (b *Buffer) Read(numBytes int16) (data []byte) {
	// detect wraparound; potentially off by 1
	fmt.Println("numBytes in Read ", numBytes)

	if b.LastRead == b.Head {
		if !b.Full {
			//fmt.Printf("Read 0 bytes:\n")
			return make([]byte, 0)
		}
	}

	if b.LastRead+numBytes <= b.Len {
		end := b.LastRead + numBytes //
		// fmt.Println("end ", end)
		data = b.Arr[b.LastRead:end]
	} else { // there is a wraparound
		// fmt.Println("wraparound")
		data = b.Arr[b.LastRead:] // first chunk: head to end of buffer
		diff := b.LastRead + numBytes - b.Len
		// fmt.Println("updating windowsize from ", b.WindowSize)
		b.WindowSize = b.Len - diff
		// fmt.Println("updating windowsize from ", b.WindowSize)
		data = append(data, b.Arr[:diff]...) // append second chunk (starting from beginning of buffer)
	}
	b.LastRead += numBytes
	b.LastRead = b.LastRead % b.Len
	if b.Head == b.LastRead {
		// fmt.Println("setting b.Full to false")
		b.Full = false
	}

	//fmt.Println("windowsize before updating in read: ", b.WindowSize)

	b.WindowSize += int16(min(int16(len(data)), b.Len))
	//fmt.Println("windowsize after updating in read: ", b.WindowSize)
	return data
}

func (b *Buffer) GetLastRead() int16 {
	return b.LastRead
}
