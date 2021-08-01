// Copyright (c) 2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package chaincfg

import (
	"encoding/hex"
	"math/big"
	"testing"
)

// TestInvalidHashStr ensures the newShaHashFromStr function panics when used to
// with an invalid hash string.
func TestInvalidHashStr(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("Expected panic for invalid hash, got nil")
		}
	}()
	newHashFromStr("banana")
}

func TestSigNetPowLimit(t *testing.T) {
	sigNetPowLimitHex, _ := hex.DecodeString(
		"00000377ae000000000000000000000000000000000000000000000000000000",
	)
	powLimit := new(big.Int).SetBytes(sigNetPowLimitHex)
	if sigNetPowLimit.Cmp(powLimit) != 0 {
		t.Fatalf("Signet PoW limit bits (%s) not equal to big int (%s)",
			sigNetPowLimit.Text(16), powLimit.Text(16))
	}

	if compactToBig(sigNetGenesisBlock.Header.Bits).Cmp(powLimit) != 0 {
		t.Fatalf("Signet PoW limit header bits (%d) not equal to big "+
			"int (%s)", sigNetGenesisBlock.Header.Bits,
			powLimit.Text(16))
	}
}

// compactToBig is a copy of the blockchain.CompactToBig function. We copy it
// here so we don't run into a circular dependency just because of a test.
func compactToBig(compact uint32) *big.Int {
	// Extract the mantissa, sign bit, and exponent.
	mantissa := compact & 0x007fffff
	isNegative := compact&0x00800000 != 0
	exponent := uint(compact >> 24)

	// Since the base for the exponent is 256, the exponent can be treated
	// as the number of bytes to represent the full 256-bit number.  So,
	// treat the exponent as the number of bytes and shift the mantissa
	// right or left accordingly.  This is equivalent to:
	// N = mantissa * 256^(exponent-3)
	var bn *big.Int
	if exponent <= 3 {
		mantissa >>= 8 * (3 - exponent)
		bn = big.NewInt(int64(mantissa))
	} else {
		bn = big.NewInt(int64(mantissa))
		bn.Lsh(bn, 8*(exponent-3))
	}

	// Make it negative if the sign bit is set.
	if isNegative {
		bn = bn.Neg(bn)
	}

	return bn
}
