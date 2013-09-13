// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package shamirsplit implements Shamir's cryptographic secret sharing
// algorithm.
package shamirsplit

import (
	"errors"
	"math/big"
	"io"
)

// Split takes a secret number and returns n shares where any k shares can be
// combined to recover the original secret. However, possession of less than k
// shares reveals nothing about the secret.
func Split(secret, modulus *big.Int, k, n int, rand io.Reader) (shares []*big.Int, err error) {
	if k < 1 || n < k {
		return nil, errors.New("invalid split parameters")
	}

	if secret.Cmp(modulus) >= 0 {
		return nil, errors.New("secret must be less than split modulus")
	}

	a := make([]*big.Int, k)
	a[0] = secret
	one := big.NewInt(1)
	modulusMinus1 := new(big.Int)
	modulusMinus1.Sub(modulus, one)

	for i := 1; i < k; i++ {
		a[i], err = randomNumber(rand, modulusMinus1)
		if err != nil {
			return
		}
		a[i].Add(a[i], one)
	}

	shares = make([]*big.Int, n)

	for i := 1; i <= n; i++ {
		bigI := big.NewInt(int64(i))
		t := new(big.Int)

		for j := 0; j < k; j++ {
			e := new(big.Int).Exp(bigI, big.NewInt(int64(j)), nil)
			e.Mul(e, a[j])
			t.Add(t, e)
		}

		t.Mod(t, modulus)
		shares[i-1] = t
	}

	return
}

// Join takes k shares that resulted from Split and recovers the original
// secret. The shares can be presented in any order, however the (zero based)
// index of each share must be known and provided in shareNumbers.
func Join(shares []*big.Int, shareNumbers []int, modulus *big.Int) (*big.Int, error) {
	if len(shares) != len(shareNumbers) {
		return nil, errors.New("lengths of shares and shareNumbers must match")
	}

	secret := new(big.Int)
	zero := new(big.Int)

	for i := 0; i < len(shares); i++ {
		if shareNumbers[i] < 0 {
			return nil, errors.New("found negative share number")
		}

		c := big.NewInt(1)
		for j := 0; j < len(shares); j++ {
			if i == j {
				continue
			}
			bigJ := big.NewInt(int64(shareNumbers[j] + 1))
			c.Mul(c, bigJ)
			bigJ.Sub(bigJ, big.NewInt(int64(shareNumbers[i]+1)))
			if bigJ.Cmp(zero) < 0 {
				bigJ.Add(bigJ, modulus)
			}

			d := new(big.Int)
			x := new(big.Int)
			y := new(big.Int)
			d.GCD(x, y, bigJ, modulus)
			if x.Cmp(zero) < 0 {
				x.Add(x, modulus)
			}
			c.Mul(c, x)
			c.Mod(c, modulus)
		}

		c.Mul(c, shares[i])
		secret.Add(secret, c)
	}

	secret.Mod(secret, modulus)
	return secret, nil
}

// randomNumber returns a uniform random value in [0, max).
func randomNumber(rand io.Reader, max *big.Int) (n *big.Int, err error) {
	k := (max.BitLen() + 7) / 8

	// r is the number of bits in the used in the most significant byte of
	// max.
	r := uint(max.BitLen() % 8)
	if r == 0 {
		r = 8
	}

	bytes := make([]byte, k)
	n = new(big.Int)

	for {
		_, err = io.ReadFull(rand, bytes)
		if err != nil {
			return
		}

		// Clear bits in the first byte to increase the probability
		// that the candidate is < max.
		bytes[0] &= uint8(int(1<<r) - 1)

		n.SetBytes(bytes)
		if n.Cmp(max) < 0 {
			return
		}
	}
}
