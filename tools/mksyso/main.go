// Command mksyso turns an application manifest into a Windows amd64 COFF object that the Go
// linker picks up as the program's resources (a *_windows_amd64.syso file next to the main
// package). The agent UI needs it: without Common Controls v6 in the manifest its windows do
// not start.
//
//	go run ./tools/mksyso -manifest cmd/agentui/agentui.manifest -o cmd/agentui/rsrc_windows_amd64.syso
package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"log"
	"os"
)

func main() {
	manifest := flag.String("manifest", "", "manifest XML file")
	out := flag.String("o", "", "output .syso file")
	flag.Parse()
	if *manifest == "" || *out == "" {
		log.Fatal("need -manifest and -o")
	}
	xml, err := os.ReadFile(*manifest)
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(*out, build(xml), 0o644); err != nil {
		log.Fatal(err)
	}
}

// build lays out one .rsrc section holding a three-level resource tree
// (RT_MANIFEST -> id 1 -> language 0x409 -> data) with a relocation for the data's address.
func build(xml []byte) []byte {
	le := binary.LittleEndian
	w := func(b *bytes.Buffer, v ...any) {
		for _, x := range v {
			binary.Write(b, le, x)
		}
	}
	dir := func(b *bytes.Buffer, id uint32, next uint32) {
		w(b, uint32(0), uint32(0), uint16(0), uint16(0), uint16(0), uint16(1)) // one ID entry
		w(b, id, next)
	}

	const (
		l2   = 24
		l3   = 48
		data = 72
		blob = 88
	)
	var sec bytes.Buffer
	dir(&sec, 24, 0x80000000|l2) // RT_MANIFEST
	dir(&sec, 1, 0x80000000|l3)  // resource id 1
	dir(&sec, 0x409, data)       // en-US
	w(&sec, uint32(blob), uint32(len(xml)), uint32(0), uint32(0))
	sec.Write(xml)
	for sec.Len()%4 != 0 {
		sec.WriteByte(0)
	}

	const hdr, shdr = 20, 40
	rawOff := uint32(hdr + shdr)
	relOff := rawOff + uint32(sec.Len())
	symOff := relOff + 10

	var f bytes.Buffer
	w(&f, uint16(0x8664), uint16(1), uint32(0), symOff, uint32(1), uint16(0), uint16(0))
	f.WriteString(".rsrc\x00\x00\x00")
	w(&f, uint32(0), uint32(0), uint32(sec.Len()), rawOff, relOff, uint32(0), uint16(1), uint16(0), uint32(0xC0000040))
	f.Write(sec.Bytes())
	w(&f, uint32(data), uint32(0), uint16(3)) // IMAGE_REL_AMD64_ADDR32NB against symbol 0
	f.WriteString(".rsrc\x00\x00\x00")
	w(&f, uint32(0), int16(1), uint16(0), uint8(3), uint8(0)) // section symbol
	w(&f, uint32(4))                                          // empty string table
	return f.Bytes()
}
