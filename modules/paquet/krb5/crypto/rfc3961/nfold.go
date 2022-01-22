package rfc3961

/*
// From [Impacket](https://github.com/SecureAuthCorp/impacket)
// https://github.com/SecureAuthCorp/impacket/blob/1dad8f7f9fee82d63c876e781f2d2bab3975f2bb/impacket/krb5/crypto.py#L117

```python
def _nfold(ba, nbytes):
    # Convert bytearray to a string of length nbytes using the RFC 3961 nfold
    # operation.

    # Rotate the bytes in ba to the right by nbits bits.
    def rotate_right(ba, nbits):
        ba = bytearray(ba)
        nbytes, remain = (nbits//8) % len(ba), nbits % 8
        return bytearray((ba[i-nbytes] >> remain) | ((ba[i-nbytes-1] << (8-remain)) & 0xff) for i in range(len(ba)))

    # Add equal-length strings together with end-around carry.
    def add_ones_complement(str1, str2):
        n = len(str1)
        v = [a + b for a, b in zip(str1, str2)]
        # Propagate carry bits to the left until there aren't any left.
        while any(x & ~0xff for x in v):
            v = [(v[i-n+1]>>8) + (v[i]&0xff) for i in range(n)]
        return bytearray(x for x in v)

    # Concatenate copies of str to produce the least common multiple
    # of len(str) and nbytes, rotating each copy of str to the right
    # by 13 bits times its list position.  Decompose the concatenation
    # into slices of length nbytes, and add them together as
    # big-endian ones' complement integers.
    slen = len(ba)
    lcm = nbytes * slen // gcd(nbytes, slen)
    bigstr = bytearray()
    for i in range(lcm//slen):
        bigstr += rotate_right(ba, 13 * i)
    slices = (bigstr[p:p+nbytes] for p in range(0, lcm, nbytes))
    return bytes(reduce(add_ones_complement, slices))
```
*/

// https://github.com/pkorobeinikov/golang-example/blob/master/math/gcd.go
// GCDRemainder calculates GCD iteratively using remainder.
func gcd(a int, b int) int {
	for b != 0 {
		a, b = b, a%b
	}
	return a
}

// Return array index as a positif number
func getIndex(i int, l int) int {
	// ((i % l) + l) % l
	i = (i % l)
	for i < 0 {
		i += l
	}

	return i
}

// Rotate the bytes in ba to the right by nbits bits.
func rotateRight(ba []byte, nbits int) []byte {
	nbytes, remain := (nbits/8)%len(ba), uint(nbits%8)
	buf := make([]byte, 0)

	for i := 0; i < len(ba); i++ {
		b1 := byte(ba[getIndex(i-nbytes, len(ba))] >> remain)
		b2 := byte((ba[getIndex(i-nbytes-1, len(ba))] << (8 - remain)) & 0xff)

		buf = append(buf, b1|b2)
	}

	return buf
}

// Add equal-length strings together with end-around carry
func addOnesComplement(str1 []byte, str2 []byte) []byte {
	n := len(str1)

	// Create a int slice to add the two byte slice
	v := make([]int, 0)
	for i := 0; i < n; i++ {
		v = append(v, int(str1[i])+int(str2[i]))
	}

	// Propagate carry bits to the left until there aren't any left.
	c := true
	for c {
		c = false
		w := make([]int, n)
		for i := 0; i < n; i++ {
			if v[i] > 0xff {
				c = true
			}

			w[i] = (v[(i+1)%n] >> 8) + (v[i] & 0xff)
		}

		v = w
	}

	// Convert the int slice to a byte slice since every element is lower thant 0x100
	buf := make([]byte, n)
	for i := 0; i < n; i++ {
		buf[i] = byte(v[i] & 0xff)
	}

	return buf
}

// n-fold is an algorithm which takes m input bits and ``stretches''
// them to form n output bits with equal contribution from each input
// bit to the output, as described in [Blumenthal96]:
func Nfold(ba []byte, nbytes int) []byte {
	slen := len(ba)

	// find Least Common Multiple (LCM) via GCD
	lcm := nbytes * slen / gcd(nbytes, slen)
	bigstr := make([]byte, 0)

	for i := 0; i < lcm/slen; i++ {
		r := rotateRight(ba, 13*i)
		bigstr = append(bigstr, r...)
	}

	nfold := make([]byte, nbytes)
	for p := 0; p < lcm; p += nbytes {
		nfold = addOnesComplement(nfold, bigstr[p:p+nbytes])
	}

	return nfold
}
