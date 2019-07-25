// Copyright (c) 2013-2014 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package base58_test

import (
	"bytes"
	"testing"

	"github.com/martinboehm/btcutil/base58"
)

var checkEncodingStringTests = []struct {
	version []byte
	hasher  base58.CksumHasher
	in      string
	out     string
}{
	{[]byte{20}, base58.Sha256D, "", "3MNQE1X"},
	{[]byte{20}, base58.Groestl512D, "", "3MMSnZL"},
	{[]byte{20, 0}, base58.Blake256D, "", "Axk2WA6L"},
	{[]byte{20}, base58.Sha256D, " ", "B2Kr6dBE"},
	{[]byte{20, 0}, base58.Blake256D, " ", "kxg5DGCa1"},
	{[]byte{20}, base58.Sha256D, "-", "B3jv1Aft"},
	{[]byte{20}, base58.Sha256D, "0", "B482yuaX"},
	{[]byte{20}, base58.Sha256D, "1", "B4CmeGAC"},
	{[]byte{20}, base58.Sha256D, "-1", "mM7eUf6kB"},
	{[]byte{20, 0}, base58.Blake256D, "-1", "4M2qnQVfVwu"},
	{[]byte{20}, base58.Sha256D, "11", "mP7BMTDVH"},
	{[]byte{20}, base58.Sha256D, "abc", "4QiVtDjUdeq"},
	{[]byte{20}, base58.Sha256D, "1234598760", "ZmNb8uQn5zvnUohNCEPP"},
	{[]byte{20}, base58.Groestl512D, "1234598760", "ZmNb8uQn5zvnUoisWKK7"},
	{[]byte{20, 0}, base58.Blake256D, "1234598760", "3UFLKR4oYrL1hSX1Eu2W3F"},
	{[]byte{20}, base58.Sha256D, "abcdefghijklmnopqrstuvwxyz", "K2RYDcKfupxwXdWhSAxQPCeiULntKm63UXyx5MvEH2"},
	{[]byte{20}, base58.Groestl512D, "abcdefghijklmnopqrstuvwxyz", "K2RYDcKfupxwXdWhSAxQPCeiULntKm63UXyx2rTuoo"},
	{[]byte{20, 0}, base58.Blake256D, "abcdefghijklmnopqrstuvwxyz", "2M5VSfthNqvveeGWTcKRgY4Rm258o4ZDKBZGkAQ799jp"},
	{[]byte{20}, base58.Sha256D, "00000000000000000000000000000000000000000000000000000000000000", "bi1EWXwJay2udZVxLJozuTb8Meg4W9c6xnmJaRDjg6pri5MBAxb9XwrpQXbtnqEoRV5U2pixnFfwyXC8tRAVC8XxnjK"},
	{[]byte{20, 0}, base58.Blake256D, "00000000000000000000000000000000000000000000000000000000000000", "3cmTs9hNQGCVmurJUgS7UokKFYZCCJWvWfYRBCaox5hXDn3Giiy1u9AEKn7vLS8K87BcDr6Ckr4JYRnnaSMRDsB49i3eU"},
}

func TestBase58Check(t *testing.T) {
	for x, test := range checkEncodingStringTests {
		// test encoding
		if res := base58.CheckEncode([]byte(test.in), test.version, test.hasher); res != test.out {
			t.Errorf("CheckEncode test #%d failed: got %s, want: %s", x, res, test.out)
		}

		// test decoding
		res, version, err := base58.CheckDecode(test.out, uint8(len(test.version)), test.hasher)
		if err != nil {
			t.Errorf("CheckDecode test #%d failed with err: %v", x, err)
		} else if !bytes.Equal(version, test.version) {
			t.Errorf("CheckDecode test #%d failed: got version: %d want: %d", x, version, test.version)
		} else if string(res) != test.in {
			t.Errorf("CheckDecode test #%d failed: got: %s want: %s", x, res, test.in)
		}
	}

	// test the few decoding failure cases
	// case 1: checksum error
	_, _, err := base58.CheckDecode("3MNQE1Y", 1, base58.Sha256D)
	if err != base58.ErrChecksum {
		t.Error("Checkdecode test failed, expected ErrChecksum")
	}
	// case 2: checksum error (valid SHA256 checksum), but we use Groestl hash
	_, _, err = base58.CheckDecode("3MNQE1X", 1, base58.Groestl512D)
	if err != base58.ErrChecksum {
		t.Error("Checkdecode(Groestl512D) test failed, expected ErrChecksum")
	}
	// case 3: invalid formats (string lengths below 5 mean the version byte and/or the checksum
	// bytes are missing).
	testString := ""
	for len := 0; len < 4; len++ {
		// make a string of length `len`
		_, _, err = base58.CheckDecode(testString, 1, base58.Sha256D)
		if err != base58.ErrInvalidFormat {
			t.Error("Checkdecode test failed, expected ErrInvalidFormat")
		}
	}

}
