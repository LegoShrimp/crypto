//Goal is to add padding to messages before encryption that will reduce
//the amount of information leaked through the length of the message.
//Specifically by O(loglog(l))

//To pad a message with this all you need to do is call Pad.
//The first parameter is a byte slice with your message in it.
//The second parameter is the number of bytes added by the encryption.
//Currently this only works if the encryption adds a static overhead.

package padding

import (
	"bytes"
	"encoding/binary"
	//	"fmt"
	"math"
)

//overhead to encode the amount of padding,
const PADLEN = 8

//the byte used to pad messages.
//0 because it makes things easier elsewhere, might need to be changed
const PADBYTE = 0x00

//Inputs:
//length int, is the length of the message.
//overhead int, is the overhead(in bytes) added by the encryption and padding
//Returns the number of bits required to store the length of the message.
func msgBits(length, overhead uint64) uint64 {
	//Plus one because if the message is a power of 2 it would be wrong
	//A message of 8 bytes, needs 4 bits. But log_2(8)=3
	return uint64(math.Ceil(math.Log2(float64(length+overhead) + 1)))
}

//Inputs:
//length int, is the length of the message.
//overhead int, is the overhead(in bytes) added by the encryption and padding
//Returns the number of leak bits.
func leakBits(length, overhead uint64) uint64 {
	//Not sure why there is +1, possibly should be removed
	return uint64(math.Ceil(math.Log2(float64(
		msgBits(length, overhead)))))
}

//Inputs:
//length int, is the length of the message.
//overhead int, is the overhead(in bytes) added by the encryption and padding
//Returns the number of bits that need to be zeroed.
func zeroBits(length, overhead uint64) uint64 {
	msg := msgBits(length, overhead)
	leak := leakBits(length, overhead)
	//	fmt.Println(msg, leak)
	return msg - leak
}

//Inputs:
//msgLen int, Is the length of the message to be padded.
//overhead int, is how much overhead the encryption,
//and padding will add to the length of the message
//Returns how many bytes of padding need to be added
//Works by masking the non zero bits to 1, then inverting and adding 1.
//Another way to do this would just be look at each bit 1 at a time
//For zeroBits
// sum+= l & (1<<i)
//Code so that if l&(1<<i) is 0 it adds 2^i, otherwise nothing
func PaddingLength(msgLen, overhead uint64) uint64 {
	paddingNeeded := uint64(msgLen + overhead)
	zeroBits := zeroBits(msgLen, overhead)

	var i, mask uint64
	//Generate a mask that we use to isolate the zeroBits bits of the length
	for i = 0; i < zeroBits; i++ {
		mask |= (1 << i)
		//fmt.Println(i, zeroBits)
	}
	//invert the mask
	mask = ^mask
	//Or the mask with our length. Now all non zero bits are 1
	paddingNeeded |= mask
	//invert l, now we have the ^l, ^l + l will give us only ones
	//So if we add 1 to that we get 0 in all of the zero bits.
	//And the next largest bit will be a 1.
	paddingNeeded = ^paddingNeeded
	paddingNeeded = paddingNeeded + 1
	//This is the case where all of the zero bits are already 0.
	if float64(paddingNeeded) == math.Pow(2, float64(zeroBits)) {
		paddingNeeded = 0
	}
	return paddingNeeded
}

//Function that checks if a message is padded correctly
//Inputs:
//msgLen int, msgLen is the length of the message to check.
//Returns true if it is an acceptable length, false otherwise.
func CheckPadding(msgLen uint64) bool {
	paddingNeeded := uint64(msgLen)
	zeroBits := zeroBits(msgLen, 0)
	var i, mask uint64
	for i = 0; i < zeroBits; i++ {
		mask |= (1 << i)
	}
	mask = ^mask
	paddingNeeded |= mask
	paddingNeeded = ^paddingNeeded
	paddingNeeded = paddingNeeded + 1
	//This is the case were the message is padded correctly
	//all bits are 0 -> all are 1 -> +1 = zeroBits^2
	if float64(paddingNeeded) == math.Pow(2, float64(zeroBits)) {
		paddingNeeded = 0
	}
	if paddingNeeded == 0 {
		return true
	}
	return false
}

//generates padding, can be later modified if something else is better.
//There is also probably a more efficient way to generate it.
//Inputs:
//paddingAmount uint64 --this is the number of bytes of padding to generate.
func GeneratePadding(paddingAmount uint64) []byte {
	padding := make([]byte, paddingAmount)
	var i uint64
	for i = 0; i < paddingAmount; i++ {
		padding[i] = PADBYTE //random choice
	}
	return padding
}

//Inputs:
//overhead int, is the number of bytes the encryption will add to the plaintext
//The system only works if the overhead from encrypting the
// message is static.
//msg []byte, is the plaintext message that needs to be padded.
//Returns a properly padded message.
func Pad(msg []byte, overhead uint64) []byte {
	padAmount := PaddingLength(uint64(len(msg)), overhead+PADLEN)
	padding := GeneratePadding(padAmount)
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, int64(padAmount))
	paddedMsg := buf.Bytes()
	paddedMsg = append(paddedMsg, msg...)
	paddedMsg = append(paddedMsg, padding...)
	return paddedMsg
}

//Inputs:
// msg []byte, is an unencrypted padded message.
//removes the padding from a message.
func UnPad(msg []byte) []byte {
	var paddingAmount uint64
	paddingAmount = binary.BigEndian.Uint64(msg[0:8])
	return msg[8 : uint64(len(msg))-paddingAmount]
}
