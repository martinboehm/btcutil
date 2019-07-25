// Copyright (c) 2013-2014 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package base58

import (
	"crypto/sha256"
	"errors"
	"github.com/Groestlcoin/go-groestl-hash/groestl"
	"github.com/dchest/blake256"
)

type CksumHasher int

// Hash function types for checksum calculation
const (
	Sha256D     CksumHasher = iota // Double SHA256
	Groestl512D                    // Double Groestl512
	Blake256D                      // Double Blake256
)

// ErrChecksum indicates that the checksum of a check-encoded string does not verify against
// the checksum.
var ErrChecksum = errors.New("checksum error")

// ErrInvalidFormat indicates that the check-encoded string has an invalid format.
var ErrInvalidFormat = errors.New("invalid format: version and/or checksum bytes missing")

// checksum: first four bytes of hash^2
func checksum(input []byte, hash CksumHasher) (cksum [4]byte) {
	switch hash {
	case Sha256D:
		h := sha256.Sum256(input)
		h2 := sha256.Sum256(h[:])
		copy(cksum[:], h2[:4])
	case Groestl512D:
		var h1, h2 [64]byte
		g := groestl.New()
		g.Write(input)
		g.Close(h1[:], 0, 0)
		g.Write(h1[:])
		g.Close(h2[:], 0, 0)
		copy(cksum[:], h2[:4])
	case Blake256D:
		h := blake256.New()
		h.Write(input)
		intermediateHash := h.Sum(nil)
		h.Reset()
		h.Write(intermediateHash)
		finalHash := h.Sum(nil)
		copy(cksum[:], finalHash)
	default:
		// Should never happen
		panic("BUG! Not all CksumHasher values are implemented.")
	}
	return
}

// CheckEncode prepends a version byte and appends a four byte checksum.
func CheckEncode(input, version []byte, hash CksumHasher) string {
	b := make([]byte, 0, len(version)+len(input)+4)
	b = append(b, version[:]...)
	b = append(b, input[:]...)
	cksum := checksum(b, hash)
	b = append(b, cksum[:]...)
	return Encode(b)
}

// CheckDecode decodes a string that was encoded with CheckEncode and verifies the checksum.
func CheckDecode(input string, versionLen uint8, hash CksumHasher) (result, version []byte, err error) {
	decoded := Decode(input)
	if len(decoded) < 5 {
		return nil, nil, ErrInvalidFormat
	}
	version = decoded[:versionLen]
	var cksum [4]byte
	copy(cksum[:], decoded[len(decoded)-4:])
	if checksum(decoded[:len(decoded)-4], hash) != cksum {
		return nil, nil, ErrChecksum
	}
	payload := decoded[versionLen : len(decoded)-4]
	result = append(result, payload...)
	return
}
