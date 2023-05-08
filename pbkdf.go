package pbes1

import (
	"fmt"
	"hash"
)

func pbkdf1(password []byte, salt []byte, len int, count int, md hash.Hash) ([]byte, error) {
	if md.BlockSize() < len {
		return nil, fmt.Errorf("too short md blocksize")
	}

	md.Write(append(password, salt...))
	h := md.Sum(nil)
	for i := 1; i < count; i++ {
		md.Reset()
		md.Write(h)
		h = md.Sum(nil)
	}

	return h[:len], nil
}
