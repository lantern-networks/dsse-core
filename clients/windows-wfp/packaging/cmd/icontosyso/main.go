// Command icontosyso turns a .ico into a .syso the Go linker embeds as a Windows icon resource.
//
// ★★ WHY THIS EXISTS RATHER THAN A DEPENDENCY. Windows 11's taskbar does not read the icon a window sets with
// WM_SETICON; it reads the icon resource compiled into the executable. Measured on this box: the title bar and
// Alt-Tab showed the mark from WM_SETICON while the taskbar kept the generic window icon, at 32px and at 48px
// alike. So the mark has to be IN the binary, and Go has no built-in way to put it there.
//
// The usual answer is a build-time module (go-winres, rsrc). This tree takes none: the output is a fixed
// artefact that changes only when the icon does, so it is generated once, committed, and the generator is kept
// beside it so the artefact can be re-derived rather than trusted. `go build` picks up any *.syso in a package
// directory automatically — there is no build step to remember and no tool to install.
//
//	go run ./clients/windows-wfp/packaging/cmd/icontosyso -in brand/lantern.ico -out rsrc_windows_amd64.syso
//
// ★ WHAT IT WRITES, so the next reader does not have to reverse it. A COFF object holding one .rsrc section:
// a three-level resource directory (type -> name -> language) carrying RT_ICON entries for each image in the
// .ico plus one RT_GROUP_ICON that indexes them, followed by the image bytes. Every data entry's address is a
// file offset that the linker must fix up, so each one gets a relocation against a single section symbol —
// that relocation table is the part it is easy to get quietly wrong, and the part the verifier at the bottom
// exists to catch.

package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"os"
)

const (
	rtIcon      = 3
	rtGroupIcon = 14
	// ★ RT_VERSION, added 2026-09-09. Measured on win-dev-1 that morning: every shipped executable had an
	// EMPTY version resource — CompanyName, ProductName and FileVersion all blank in the properties dialog and
	// in Get-Item(...).VersionInfo. A signed product that will not say who published it or what version it is
	// forces every administrator who inventories it to open the Authenticode signature instead, and every
	// software-inventory tool that reads those fields to report nothing at all. The Go toolchain writes no
	// version resource of its own, so it has to be supplied here beside the icon rather than wished for.
	//
	// ★ It stays DEPLOYMENT-INDEPENDENT, which is the constraint the signed artifacts are now held to: this
	// carries the publisher and the product version and nothing about any organization, edge, key or tenant.
	rtVersion = 16

	imageFileMachineAMD64 = 0x8664
	imageFileMachineARM64 = 0xAA64

	// IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ
	sectionCharacteristics = 0x40000040
	// IMAGE_REL_AMD64_ADDR32NB / IMAGE_REL_ARM64_ADDR32NB — an RVA, which is what a resource data entry holds.
	relAMD64Addr32NB = 0x0003
	relARM64Addr32NB = 0x0002
)

// icoEntry is one image inside the .ico, as the directory describes it.
type icoEntry struct {
	width, height byte
	colorCount    byte
	reserved      byte
	planes        uint16
	bitCount      uint16
	bytesInRes    uint32
	offset        uint32
	data          []byte
}

func main() {
	in := flag.String("in", "", "path to the .ico to embed")
	out := flag.String("out", "", "path to the .syso to write")
	arch := flag.String("arch", "amd64", "amd64 or arm64")
	// ★ The version resource. Optional so the icon path keeps working unchanged, but the build passes it for
	// every binary: an executable that ships without one shows a blank properties dialog, which is what this
	// was added to fix. -in may be empty when a binary wants a version and no icon.
	ver := flag.String("version", "", "product version to embed, e.g. 0.3.0 (empty = no version resource)")
	desc := flag.String("description", "", "FileDescription, e.g. \"DSSE steering agent\"")
	origName := flag.String("original-name", "", "OriginalFilename, e.g. dsse-steer.exe")
	flag.Parse()
	if *out == "" || (*in == "" && *ver == "") {
		fmt.Fprintln(os.Stderr, "icontosyso: -out is required, and at least one of -in or -version")
		os.Exit(2)
	}
	var entries []icoEntry
	if *in != "" {
		raw, err := os.ReadFile(*in)
		if err != nil {
			fmt.Fprintln(os.Stderr, "icontosyso:", err)
			os.Exit(1)
		}
		entries, err = parseICO(raw)
		if err != nil {
			fmt.Fprintln(os.Stderr, "icontosyso:", err)
			os.Exit(1)
		}
	}
	var verPayload []byte
	if *ver != "" {
		maj, min, patch, build := parseVersion(*ver)
		name := *origName
		if name == "" {
			name = "dsse.exe"
		}
		verPayload = versionResource(maj, min, patch, build, [][2]string{
			{"CompanyName", "Lantern Networks, Inc."},
			{"ProductName", "Lantern DSSE Agent"},
			{"FileDescription", *desc},
			{"OriginalFilename", name},
			{"FileVersion", *ver},
			{"ProductVersion", *ver},
			{"LegalCopyright", "Lantern Networks, Inc."},
		})
	}
	obj, err := buildCOFF(entries, verPayload, *arch)
	if err != nil {
		fmt.Fprintln(os.Stderr, "icontosyso:", err)
		os.Exit(1)
	}
	if err := os.WriteFile(*out, obj, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "icontosyso:", err)
		os.Exit(1)
	}
	fmt.Printf("icontosyso: %s -> %s (%d icon(s), %d bytes)\n", *in, *out, len(entries), len(obj))
}

// parseICO reads the ICONDIR and its entries. It refuses rather than guesses: a truncated .ico that produced a
// half-written resource would show up as a missing icon much later, with nothing pointing back here.
func parseICO(b []byte) ([]icoEntry, error) {
	if len(b) < 6 {
		return nil, fmt.Errorf("not an .ico: %d bytes", len(b))
	}
	if binary.LittleEndian.Uint16(b[0:]) != 0 || binary.LittleEndian.Uint16(b[2:]) != 1 {
		return nil, fmt.Errorf("not an .ico: bad ICONDIR header")
	}
	n := int(binary.LittleEndian.Uint16(b[4:]))
	if n == 0 {
		return nil, fmt.Errorf(".ico carries no images")
	}
	if len(b) < 6+16*n {
		return nil, fmt.Errorf(".ico truncated: %d entries declared, %d bytes", n, len(b))
	}
	out := make([]icoEntry, 0, n)
	for i := 0; i < n; i++ {
		o := 6 + 16*i
		e := icoEntry{
			width: b[o], height: b[o+1], colorCount: b[o+2], reserved: b[o+3],
			planes:     binary.LittleEndian.Uint16(b[o+4:]),
			bitCount:   binary.LittleEndian.Uint16(b[o+6:]),
			bytesInRes: binary.LittleEndian.Uint32(b[o+8:]),
			offset:     binary.LittleEndian.Uint32(b[o+12:]),
		}
		end := int(e.offset) + int(e.bytesInRes)
		if int(e.offset) >= len(b) || end > len(b) {
			return nil, fmt.Errorf("entry %d points outside the file (%d..%d of %d)", i, e.offset, end, len(b))
		}
		e.data = b[e.offset:end]
		out = append(out, e)
	}
	return out, nil
}

// resDataEntry is one IMAGE_RESOURCE_DATA_ENTRY: where the bytes are, and how many.
type resDataEntry struct {
	dataRVAOffset int // where in the section the RVA field sits, so a relocation can be emitted for it
	dataOffset    int // where in the section the bytes themselves sit
	size          int
}

func buildCOFF(entries []icoEntry, verPayload []byte, arch string) ([]byte, error) {
	machine, relType := uint16(imageFileMachineAMD64), uint16(relAMD64Addr32NB)
	if arch == "arm64" {
		machine, relType = imageFileMachineARM64, relARM64Addr32NB
	}

	// The resource tree: two types (RT_ICON with one name per image, RT_GROUP_ICON with one name), each name
	// carrying a single language (1033), each language pointing at a data entry.
	type leaf struct {
		typeID, nameID uint32
		payload        []byte
	}
	leaves := make([]leaf, 0, len(entries)+2)
	for i, e := range entries {
		leaves = append(leaves, leaf{typeID: rtIcon, nameID: uint32(i + 1), payload: e.data})
	}
	if len(entries) > 0 {
		leaves = append(leaves, leaf{typeID: rtGroupIcon, nameID: 1, payload: groupIcon(entries)})
	}
	if len(verPayload) > 0 {
		leaves = append(leaves, leaf{typeID: rtVersion, nameID: 1, payload: verPayload})
	}
	if len(leaves) == 0 {
		return nil, fmt.Errorf("nothing to embed: no icon and no version")
	}

	// ---- lay the section out -------------------------------------------------------------------------
	// Level 1 (types), then level 2 (names) per type, then level 3 (languages) per name, then the data
	// entries, then the payloads. Offsets are computed first because a directory entry has to point forward.
	// ★ Types must be listed in ASCENDING numeric order. The resource directory is a sorted structure and a
	// loader that binary-searches it will not find an out-of-order entry — silently, which is this file's
	// recurring failure mode. RT_ICON(3) < RT_GROUP_ICON(14) < RT_VERSION(16).
	types := []uint32{}
	if len(entries) > 0 {
		types = append(types, rtIcon, rtGroupIcon)
	}
	if len(verPayload) > 0 {
		types = append(types, rtVersion)
	}
	namesPerType := map[uint32][]leaf{}
	for _, l := range leaves {
		namesPerType[l.typeID] = append(namesPerType[l.typeID], l)
	}

	const dirSize, dirEntrySize, dataEntrySize = 16, 8, 16
	pos := dirSize + dirEntrySize*len(types) // level 1
	nameDirOffset := map[uint32]int{}
	for _, t := range types {
		nameDirOffset[t] = pos
		pos += dirSize + dirEntrySize*len(namesPerType[t])
	}
	langDirOffset := make([]int, 0, len(leaves))
	for range leaves {
		langDirOffset = append(langDirOffset, pos)
		pos += dirSize + dirEntrySize // one language each
	}
	dataEntryOffset := make([]int, 0, len(leaves))
	for range leaves {
		dataEntryOffset = append(dataEntryOffset, pos)
		pos += dataEntrySize
	}
	payloadOffset := make([]int, 0, len(leaves))
	for _, l := range leaves {
		if pos%8 != 0 { // payloads are 8-aligned; the loader does not require it but every real .rsrc does it
			pos += 8 - pos%8
		}
		payloadOffset = append(payloadOffset, pos)
		pos += len(l.payload)
	}
	sectionSize := pos

	sec := make([]byte, sectionSize)
	put16 := func(off int, v uint16) { binary.LittleEndian.PutUint16(sec[off:], v) }
	put32 := func(off int, v uint32) { binary.LittleEndian.PutUint32(sec[off:], v) }

	// level 1: the type directory
	put16(12, 0)                  // NumberOfNamedEntries
	put16(14, uint16(len(types))) // NumberOfIdEntries
	for i, t := range types {
		e := dirSize + dirEntrySize*i
		put32(e, t)
		put32(e+4, uint32(nameDirOffset[t])|0x80000000) // high bit: points at another directory
	}

	// level 2: one name directory per type
	leafIndex := 0
	leafOrder := make([]leaf, 0, len(leaves))
	for _, t := range types {
		d := nameDirOffset[t]
		ns := namesPerType[t]
		put16(d+12, 0)
		put16(d+14, uint16(len(ns)))
		for i, l := range ns {
			e := d + dirSize + dirEntrySize*i
			put32(e, l.nameID)
			put32(e+4, uint32(langDirOffset[leafIndex])|0x80000000)
			leafOrder = append(leafOrder, l)
			leafIndex++
		}
	}

	// level 3: one language directory per name, and the data entry it points at
	relocs := make([]resDataEntry, 0, len(leafOrder))
	for i := range leafOrder {
		d := langDirOffset[i]
		put16(d+12, 0)
		put16(d+14, 1)
		put32(d+dirSize, 1033) // en-US
		put32(d+dirSize+4, uint32(dataEntryOffset[i]))

		de := dataEntryOffset[i]
		put32(de, uint32(payloadOffset[i])) // OffsetToData — an RVA the linker fixes up
		put32(de+4, uint32(len(leafOrder[i].payload)))
		put32(de+8, 0) // CodePage
		put32(de+12, 0)
		relocs = append(relocs, resDataEntry{dataRVAOffset: de, dataOffset: payloadOffset[i], size: len(leafOrder[i].payload)})
		copy(sec[payloadOffset[i]:], leafOrder[i].payload)
	}

	// ---- the object file ------------------------------------------------------------------------------
	const fileHeaderSize, sectionHeaderSize, symbolSize = 20, 40, 18
	secDataPos := fileHeaderSize + sectionHeaderSize
	relocPos := secDataPos + sectionSize
	relocSize := 10 * len(relocs)
	symPos := relocPos + relocSize

	var buf bytes.Buffer
	w16 := func(v uint16) { binary.Write(&buf, binary.LittleEndian, v) }
	w32 := func(v uint32) { binary.Write(&buf, binary.LittleEndian, v) }

	// IMAGE_FILE_HEADER
	w16(machine)
	w16(1) // one section
	w32(0) // TimeDateStamp: zero, so the artefact is byte-identical for the same icon
	w32(uint32(symPos))
	w32(1) // one symbol: the section itself, which every relocation is against
	w16(0) // no optional header
	w16(0)

	// section header
	buf.WriteString(".rsrc\x00\x00\x00")
	w32(0) // VirtualSize
	w32(0) // VirtualAddress
	w32(uint32(sectionSize))
	w32(uint32(secDataPos))
	w32(uint32(relocPos))
	w32(0) // PointerToLinenumbers
	w16(uint16(len(relocs)))
	w16(0)
	w32(sectionCharacteristics)

	buf.Write(sec)

	// relocations: each data entry's OffsetToData is an RVA into this section
	for _, r := range relocs {
		w32(uint32(r.dataRVAOffset)) // VirtualAddress
		w32(0)                       // SymbolTableIndex: the section symbol
		w16(relType)
	}

	// symbol table: one static symbol naming the section
	buf.WriteString(".rsrc\x00\x00\x00")
	w32(0)           // Value
	w16(1)           // SectionNumber
	w16(0)           // Type
	buf.WriteByte(3) // StorageClass = IMAGE_SYM_CLASS_STATIC
	buf.WriteByte(0) // NumberOfAuxSymbols
	w32(4)           // string table: size only, no entries

	obj := buf.Bytes()
	if err := verify(obj, len(relocs), sectionSize); err != nil {
		return nil, err
	}
	return obj, nil
}

// groupIcon builds the RT_GROUP_ICON payload: the ICONDIR again, but with each entry's trailing field being
// the RT_ICON resource id rather than a file offset. Getting that field wrong is the classic way to produce an
// object that links cleanly and shows no icon.
func groupIcon(entries []icoEntry) []byte {
	var b bytes.Buffer
	binary.Write(&b, binary.LittleEndian, uint16(0))
	binary.Write(&b, binary.LittleEndian, uint16(1))
	binary.Write(&b, binary.LittleEndian, uint16(len(entries)))
	for i, e := range entries {
		b.WriteByte(e.width)
		b.WriteByte(e.height)
		b.WriteByte(e.colorCount)
		b.WriteByte(e.reserved)
		binary.Write(&b, binary.LittleEndian, e.planes)
		binary.Write(&b, binary.LittleEndian, e.bitCount)
		binary.Write(&b, binary.LittleEndian, e.bytesInRes)
		binary.Write(&b, binary.LittleEndian, uint16(i+1)) // the RT_ICON id, not an offset
	}
	return b.Bytes()
}

// verify re-reads what was just written, because a malformed COFF object does not fail loudly: it links, and
// the icon is simply absent months later.
func verify(obj []byte, wantRelocs, wantSectionSize int) error {
	if len(obj) < 60 {
		return fmt.Errorf("object too small: %d bytes", len(obj))
	}
	if n := binary.LittleEndian.Uint16(obj[2:]); n != 1 {
		return fmt.Errorf("expected 1 section, header says %d", n)
	}
	name := string(bytes.TrimRight(obj[20:28], "\x00"))
	if name != ".rsrc" {
		return fmt.Errorf("section is %q, not .rsrc", name)
	}
	if got := int(binary.LittleEndian.Uint32(obj[36:])); got != wantSectionSize {
		return fmt.Errorf("SizeOfRawData %d, section built as %d", got, wantSectionSize)
	}
	if got := int(binary.LittleEndian.Uint16(obj[52:])); got != wantRelocs {
		return fmt.Errorf("NumberOfRelocations %d, %d were emitted", got, wantRelocs)
	}
	dataPos := int(binary.LittleEndian.Uint32(obj[40:]))
	relocPos := int(binary.LittleEndian.Uint32(obj[44:]))
	if dataPos+wantSectionSize != relocPos {
		return fmt.Errorf("section data ends at %d but relocations start at %d", dataPos+wantSectionSize, relocPos)
	}
	if relocPos+10*wantRelocs > len(obj) {
		return fmt.Errorf("relocation table runs past the end of the object")
	}
	return nil
}

// ---------------------------------------------------------------------------------------------------------
// VS_VERSIONINFO
//
// ★ WHY THIS IS BUILT BY HAND AND NOT WITH A LIBRARY. The structure is a tree of variable-length blocks whose
// every node repeats its own length, and where each node and each value must start on a 32-bit boundary. Get a
// padding byte wrong and Windows does not complain: it silently shows nothing, which is exactly the state this
// was written to fix. So the writer below computes each block's length AFTER its children are laid down, and
// pads at the two places the format requires — after the key, and after the value.
//
// Layout, per the documented VS_VERSIONINFO / StringFileInfo / VarFileInfo shapes:
//
//   VS_VERSIONINFO  key "VS_VERSION_INFO", value = VS_FIXEDFILEINFO (52 bytes)
//     StringFileInfo  key "StringFileInfo"
//       StringTable   key "040904B0"        (US English, Unicode — 0x0409, 0x04B0)
//         String      key "CompanyName"      value "Lantern Networks, Inc."
//         …
//     VarFileInfo     key "VarFileInfo"
//       Var           key "Translation"      value 0x0409 0x04B0 as two WORDs
//
// The two codepage numbers appear twice and MUST agree: the StringTable is NAMED by them as hex text, and the
// Var block repeats them as binary. A reader that finds no matching pair falls back to showing nothing.

type verNode struct {
	key      string
	value    []byte // raw value bytes; for text values this is UTF-16 including the terminator
	isText   bool   // wType: 1 = text, 0 = binary. Windows uses it to interpret wValueLength's unit.
	children []*verNode
}

func utf16z(s string) []byte {
	b := make([]byte, 0, len(s)*2+2)
	for _, r := range s {
		b = append(b, byte(r), byte(r>>8))
	}
	return append(b, 0, 0)
}

// padTo4 pads b so that (headerLen + len(b)) is a multiple of four.
//
// ★ THE OFF-BY-SIX THAT PRODUCES A SILENTLY EMPTY PROPERTIES DIALOG. Alignment in this format is measured from
// the start of the NODE, and every node begins with a six-byte header (wLength, wValueLength, wType) before its
// key. Padding the body alone to a multiple of four leaves the real offset at 6 mod 4 = 2, and Windows then
// reads the value at the wrong place — it does not report an error, it shows blank fields. Measured on
// win-dev-1 2026-09-09: the resource was present in .rsrc, both strings were findable in the binary, and
// VersionInfo returned empty for every field until this accounted for the header.
func padTo4(b []byte, headerLen int) []byte {
	for (headerLen+len(b))%4 != 0 {
		b = append(b, 0)
	}
	return b
}

// marshal writes one node. wValueLength counts CHARACTERS for a text value and BYTES for a binary one — the
// single most common way to get this structure subtly wrong, so it is stated here rather than inferred.
func (n *verNode) marshal() []byte {
	const headerLen = 6 // wLength, wValueLength, wType — the key starts AFTER these, so alignment counts them
	var body []byte
	body = append(body, utf16z(n.key)...)
	body = padTo4(body, headerLen)
	if len(n.value) > 0 {
		body = append(body, n.value...)
		body = padTo4(body, headerLen)
	}
	for _, c := range n.children {
		body = append(body, c.marshal()...)
	}
	valueLen := len(n.value)
	if n.isText {
		valueLen = len(n.value) / 2 // characters, including the terminating NUL
	}
	head := make([]byte, 6)
	binary.LittleEndian.PutUint16(head[0:], uint16(6+len(body)))
	binary.LittleEndian.PutUint16(head[2:], uint16(valueLen))
	if n.isText {
		binary.LittleEndian.PutUint16(head[4:], 1)
	}
	return append(head, body...)
}

// fixedFileInfo is the 52-byte VS_FIXEDFILEINFO. The version appears here as numbers AND in the string block
// as text; a mismatch between them is legal and confusing, so both come from the same parsed value.
func fixedFileInfo(maj, min, patch, build uint16) []byte {
	b := make([]byte, 52)
	binary.LittleEndian.PutUint32(b[0:], 0xFEEF04BD) // dwSignature
	binary.LittleEndian.PutUint32(b[4:], 0x00010000) // dwStrucVersion 1.0
	binary.LittleEndian.PutUint16(b[8:], min)        // FileVersionMS: high word is major, low is minor
	binary.LittleEndian.PutUint16(b[10:], maj)
	binary.LittleEndian.PutUint16(b[12:], build) // FileVersionLS
	binary.LittleEndian.PutUint16(b[14:], patch)
	binary.LittleEndian.PutUint16(b[16:], min) // ProductVersion, same value
	binary.LittleEndian.PutUint16(b[18:], maj)
	binary.LittleEndian.PutUint16(b[20:], build)
	binary.LittleEndian.PutUint16(b[22:], patch)
	binary.LittleEndian.PutUint32(b[24:], 0x3F) // dwFileFlagsMask
	binary.LittleEndian.PutUint32(b[32:], 0x4)  // dwFileOS = VOS__WINDOWS32
	binary.LittleEndian.PutUint32(b[36:], 0x1)  // dwFileType = VFT_APP
	return b
}

// versionResource builds the RT_VERSION payload. fields is ordered so the properties dialog reads sensibly.
func versionResource(maj, min, patch, build uint16, fields [][2]string) []byte {
	strs := make([]*verNode, 0, len(fields))
	for _, f := range fields {
		strs = append(strs, &verNode{key: f[0], value: utf16z(f[1]), isText: true})
	}
	root := &verNode{
		key:   "VS_VERSION_INFO",
		value: fixedFileInfo(maj, min, patch, build),
		children: []*verNode{
			{key: "StringFileInfo", children: []*verNode{
				{key: "040904B0", children: strs},
			}},
			{key: "VarFileInfo", children: []*verNode{
				{key: "Translation", value: []byte{0x09, 0x04, 0xB0, 0x04}},
			}},
		},
	}
	return root.marshal()
}

// parseVersion splits "0.3.0" or "0.3.0.7" into four numbers. Anything it cannot read becomes zero rather than
// an error: a missing build number is not a reason to ship a binary with no version resource at all.
func parseVersion(s string) (maj, min, patch, build uint16) {
	parts := bytes.SplitN([]byte(s), []byte("."), 5)
	out := [4]uint16{}
	for i := 0; i < 4 && i < len(parts); i++ {
		n := 0
		for _, c := range parts[i] {
			if c < '0' || c > '9' {
				break
			}
			n = n*10 + int(c-'0')
		}
		if n > 0xFFFF {
			n = 0xFFFF
		}
		out[i] = uint16(n)
	}
	return out[0], out[1], out[2], out[3]
}
