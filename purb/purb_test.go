package purb

import (
	//	"bufio"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/cipher/aes"
	//	"time"
	//	"github.com/dedis/crypto/config"
	"github.com/dedis/crypto/edwards"
	"github.com/dedis/crypto/padding"
	"github.com/dedis/crypto/random"
	"io/ioutil"
	"os"
	"testing"
)

// Simple harness to create lots of fake ciphersuites out of a few real ones,
// for testing purposes.
type fakeSuite struct {
	abstract.Suite
	idx int
}

func (f *fakeSuite) String() string {
	return fmt.Sprintf("%s(%d)", f.Suite.String(), f.idx)
}

func TestPurb(t *testing.T) {

	realSuites := []abstract.Suite{
		edwards.NewAES128SHA256Ed25519(true),
		edwards.NewAES128SHA256Ed1174(true),
	}

	fakery := 1
	nentries := 10
	datalen := DATALEN

	suites := make([]abstract.Suite, 0)
	for i := range realSuites {
		real := realSuites[i]
		for j := 0; j < fakery; j++ {
			suites = append(suites, &fakeSuite{real, j})
		}
	}

	nlevels := 5
	suiteLevel := make(map[abstract.Suite]int)
	entries := make([]Entry, 0)
	suiteEntry := make(map[string][]int)
	for i := range suites {
		suiteLevel[suites[i]] = nlevels
		nlevels++ // vary it a bit for testing
		ents := make([]int, nlevels)
		for j := 0; j < nlevels; j++ {
			ents[j] = j * KEYLEN
		}
		suiteEntry[suites[i].String()] = ents

		// Create some entrypoints with this suite
		s := suites[i]
		for j := 0; j < nentries; j++ {
			pri := s.Scalar().Pick(random.Stream)
			pub := s.Point().Mul(nil, pri)
			data := make([]byte, datalen-16)
			entries = append(entries, Entry{s, pri, pub, data, nil, nil, nil})
		}
	}

	w := Writer{}
	hdrend, err := w.Layout(entries, random.Stream, suiteEntry)
	if err != nil {
		t.Log(err)
		t.FailNow()
	}

	key, _ := hex.DecodeString("9a4fea86a621a91ab371e492457796c0")
	//Probably insecure way to use it.

	cipher := abstract.Cipher(aes.NewCipher128(key))
	msg2 := ("This is the message!")
	for i := 0; i < 10; i++ {
		msg2 += msg2
	}
	msg := []byte(msg2)
	//from testing
	encOverhead := 16
	msg = padding.PadGeneric(msg, uint64(encOverhead+hdrend))
	enc := make([]byte, 0)
	enc = cipher.Seal(enc, msg)
	//encrypt message
	//w.layout.reserve(hdrend, hdrend+len(msg), true, "message")
	//Now test Write, need to fill all entry point
	fmt.Println("Writing Message")
	byteLen := make([]byte, 8)
	binary.BigEndian.PutUint64(byteLen, uint64(hdrend))
	for i := range w.entries {
		w.entries[i].Data = append(byteLen, key...)
	}
	encMessage := w.Write(random.Stream)
	encMessage = append(encMessage, enc...)
	if padding.CheckZeroBits(uint64(len(encMessage))) != true {
		panic("not padded correctly")
	}
	fmt.Println(len(encMessage), hdrend)
	err = ioutil.WriteFile("test.bin", encMessage, 0644)
	if err != nil {
		panic(err)
	}
	//Now test the decoding.
	encFile := make([]byte, 0)
	encFile, err = ioutil.ReadFile("test.bin")
	if err != nil {
		panic(err)
	}
	for i := range entries {
		if i%2 == 0 {
			continue
		}
		ent := entries[i]
		_, msgL := AttemptDecode(ent.Suite, ent.PriKey, suiteEntry, encFile, random.Stream)
		if msgL == nil {
			fmt.Println("Could not decrypt", ent, "\n")
			continue
		}

		msgL = padding.UnPadGeneric(msgL)
		//fmt.Println(ent)
		//fmt.Println(len(msgL), string(msgL), "\n\n")

	}
}
func TestPlaceHash(t *testing.T) {
	w := Writer{}
	w.layout.reset()

	for i := uint(0); i < 8; i++ {
		x := random.Uint64(random.Stream)
		fmt.Println("hash:", x)
		w.PlaceHash(uint(x))
	}
	fmt.Println("hash test layout")
	w.layout.dump()
}
func TestWritePurb(t *testing.T) {
	//simple test with one suite
	suite := edwards.NewAES128SHA256Ed1174(true)
	nentries := 3
	entries := make([]Entry, 0)
	suiteEntry := make(map[string][]int)
	nlevels := 1
	ents := make([]int, nlevels)
	for j := 0; j < nlevels; j++ {
		ents[j] = j * DATALEN
	}
	suiteEntry[suite.String()] = ents
	// Create some entrypoints with this suite
	s := suite
	for j := 0; j < nentries; j++ {
		pri := s.Scalar().Pick(random.Stream)
		pub := s.Point().Mul(nil, pri)
		data := make([]byte, DATALEN)
		entries = append(entries, Entry{s, pri, pub, data, nil, nil, nil})
	}
	msg := "This is the message! It will be stored as a file!! for suite: " + suite.String()
	//	for i, _ := range entries {
	//		msg += entries[i].PubKey.String()
	//	}
	//TODO writePurb shouldn't exist, writing the purb to a file is the applications job
	enc, _ := GenPurb(entries, suiteEntry, []byte(msg), true)
	err := ioutil.WriteFile("test.purb", enc, 0644)
	if err != nil {
		panic(err)
	}

	file, _ := os.Create("keyfile1")
	i, err := entries[0].PriKey.MarshalTo(file)
	if err != nil {
		fmt.Println(err, i)
	}
	file, _ = os.Create("keyfile2")
	i, err = entries[1].PriKey.MarshalTo(file)
	if err != nil {
		fmt.Println(err, i)
	}
	file, _ = os.Create("keyfile3")
	i, err = entries[2].PriKey.MarshalTo(file)
	if err != nil {
		fmt.Println(err, i)
	}
}

//Reads single ed25519 private keys from single files
func TestReadPurbFromFile(t *testing.T) {
	//get a public key
	//Problem need to know the suite already I think.
	fmt.Println("Testing reading purb from file")
	suite := edwards.NewAES128SHA256Ed1174(true)
	suiteEntry := make(map[string][]int)
	nlevels := 1
	ents := make([]int, nlevels)
	for j := 0; j < nlevels; j++ {
		ents[j] = j * DATALEN
	}
	suiteEntry[suite.String()] = ents
	file, err := os.Open("keyfile1")
	priKey := suite.Scalar()
	something, err := priKey.UnmarshalFrom(file)
	if err != nil {
		fmt.Println(something, err)
	}
	encFile := make([]byte, 0)
	encFile, err = ioutil.ReadFile("test.purb")
	if padding.CheckZeroBits(uint64(len(encFile))) != true {
		panic("not padded correctly")
	}
	if err != nil {
		fmt.Println(err)
	}
	_, msgL := AttemptDecode(suite, priKey, suiteEntry, encFile, random.Stream)
	if msgL == nil {
		fmt.Println("Could not decrypt")
	} else {
		msgL = padding.UnPadGeneric(msgL)
		fmt.Println(len(msgL), string(msgL))
	}
	file, err = os.Open("keyfile2")
	something, err = priKey.UnmarshalFrom(file)
	_, msgL = AttemptDecode(suite, priKey, suiteEntry, encFile, random.Stream)
	if msgL == nil {
		fmt.Println("Could not decrypt")
	} else {
		msgL = padding.UnPadGeneric(msgL)
		fmt.Println(len(msgL), string(msgL))
	}
	file, err = os.Open("keyfile3")
	something, err = priKey.UnmarshalFrom(file)
	_, msgL = AttemptDecode(suite, priKey, suiteEntry, encFile, random.Stream)
	if msgL == nil {
		fmt.Println("Could not decrypt")
	} else {
		msgL = padding.UnPadGeneric(msgL)
		fmt.Println(len(msgL), string(msgL))
	}
	fmt.Println(something)
}
