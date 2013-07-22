// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package shamirsplit

import (
	"crypto/rand"
	"math/big"
	"testing"
)

// 2^2048 - 2^1984 - 1 + 2^64 * { [2^1918 pi] + 124476 } from RFC3526
const modulusStr = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF"

func TestSplitting(t *testing.T) {
	const k = 10
	const n = 100

	secret := big.NewInt(42)
	modulus, _ := new(big.Int).SetString(modulusStr, 16)
	shares, err := Split(secret, modulus, k, n, rand.Reader)
	if err != nil {
		t.Errorf("error while splitting: %s", err)
		return
	}

	if len(shares) != n {
		t.Errorf("too few shares returned")
		return
	}

	shareNumbers := make([]int, n)
	for i := 0; i < n; i++ {
		shareNumbers[i] = i
	}

	for i := 0; i < n-k; i++ {
		result, err := Join(shares[i:k+i], shareNumbers[i:k+i], modulus)
		if err != nil {
			t.Errorf("failed to join shares: %s", err)
		}

		if result.Cmp(secret) != 0 {
			t.Errorf("Join returned wrong value with %d shares (want: %s, got: %s)", i, secret, result)
		}
	}
}
