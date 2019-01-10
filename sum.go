package multihash

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"

	sha3 "golang.org/x/crypto/sha3"
)

// ErrSumNotSupported is returned when the Sum function code is not implemented
var ErrSumNotSupported = errors.New("Function not implemented. Complain to lib maintainer.")

var ErrLenTooLarge = errors.New("requested length was too large for digest")

// HashFunc is a hash function that hashes data into digest.
//
// The length is the size the digest will be truncated to. While the hash
// function isn't responsible for truncating the digest, it may want to error if
// the length is invalid for the hash function (e.g., truncation would make the
// hash useless).
type HashFunc func(data []byte, length int) (digest []byte, err error)

// funcTable maps multicodec values to hash functions.
var funcTable = make(map[uint64]HashFunc)

// Sum obtains the cryptographic sum of a given buffer. The length parameter
// indicates the length of the resulting digest and passing a negative value
// use default length values for the selected hash function.
func Sum(data []byte, code uint64, length int) (Multihash, error) {
	if !ValidCode(code) {
		return nil, fmt.Errorf("invalid multihash code %d", code)
	}

	if length < 0 {
		var ok bool
		length, ok = DefaultLengths[code]
		if !ok {
			return nil, fmt.Errorf("no default length for code %d", code)
		}
	}

	hashFunc, ok := funcTable[code]
	if !ok {
		return nil, ErrSumNotSupported
	}

	d, err := hashFunc(data, length)
	if err != nil {
		return nil, err
	}
	if len(d) < length {
		return nil, ErrLenTooLarge
	}

	if length >= 0 {
		d = d[:length]
	}
	return Encode(d, code)
}

func sumID(data []byte, length int) ([]byte, error) {
	if length >= 0 && length != len(data) {
		return nil, fmt.Errorf("the length of the identity hash (%d) must be equal to the length of the data (%d)",
			length, len(data))

	}
	return data, nil
}

func sumSHA1(data []byte, length int) ([]byte, error) {
	a := sha1.Sum(data)
	return a[0:20], nil
}

func sumSHA256(data []byte, length int) ([]byte, error) {
	a := sha256.Sum256(data)
	return a[0:32], nil
}

func sumMD5(data []byte, length int) ([]byte, error) {
	a := md5.Sum(data)
	return a[0:md5.Size], nil
}

func sumDoubleSHA256(data []byte, length int) ([]byte, error) {
	val, _ := sumSHA256(data, len(data))
	return sumSHA256(val, len(val))
}

func sumSHA512(data []byte, length int) ([]byte, error) {
	a := sha512.Sum512(data)
	return a[0:64], nil
}

func sumSHA3_512(data []byte, length int) ([]byte, error) {
	a := sha3.Sum512(data)
	return a[:], nil
}

func sumSHAKE128(data []byte, length int) ([]byte, error) {
	bytes := make([]byte, 32)
	sha3.ShakeSum128(bytes, data)
	return bytes, nil
}

func sumSHAKE256(data []byte, length int) ([]byte, error) {
	bytes := make([]byte, 64)
	sha3.ShakeSum256(bytes, data)
	return bytes, nil
}

func sumSHA3_384(data []byte, length int) ([]byte, error) {
	a := sha3.Sum384(data)
	return a[:], nil
}

func sumSHA3_256(data []byte, length int) ([]byte, error) {
	a := sha3.Sum256(data)
	return a[:], nil
}

func sumSHA3_224(data []byte, length int) ([]byte, error) {
	a := sha3.Sum224(data)
	return a[:], nil
}

func registerStdlibHashFuncs() {
	RegisterHashFunc(IDENTITY, sumID)
	RegisterHashFunc(SHA1, sumSHA1)
	RegisterHashFunc(SHA2_512, sumSHA512)
	RegisterHashFunc(MD5, sumMD5)
}

func registerNonStdlibHashFuncs() {
	RegisterHashFunc(SHA2_256, sumSHA256)
	RegisterHashFunc(DBL_SHA2_256, sumDoubleSHA256)

	RegisterHashFunc(SHA3_224, sumSHA3_224)
	RegisterHashFunc(SHA3_256, sumSHA3_256)
	RegisterHashFunc(SHA3_384, sumSHA3_384)
	RegisterHashFunc(SHA3_512, sumSHA3_512)

	RegisterHashFunc(SHAKE_128, sumSHAKE128)
	RegisterHashFunc(SHAKE_256, sumSHAKE256)
}

func init() {
	registerStdlibHashFuncs()
	registerNonStdlibHashFuncs()
}

// RegisterHashFunc adds an entry to the package-level code -> hash func map.
// The hash function must return at least the requested number of bytes. If it
// returns more, the hash will be truncated.
func RegisterHashFunc(code uint64, hashFunc HashFunc) error {
	if !ValidCode(code) {
		return fmt.Errorf("code %v not valid", code)
	}

	_, ok := funcTable[code]
	if ok {
		return fmt.Errorf("hash func for code %v already registered", code)
	}

	funcTable[code] = hashFunc
	return nil
}
