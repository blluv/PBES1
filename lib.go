package pbes1

import (
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
	"crypto/sha1"
	"crypto/x509/pkix"
	"encoding/asn1"
	"hash"
)

var (
	oidPBEMD5DESCBC  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 3}
	oidPBEMD5RC2CBC  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 6}
	oidPBESHA1DESCBC = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 10}
	oidPBESHA1RC2CBC = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 11}
)

type encryptedPrivateKeyInfo struct {
	EncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedData       []byte
}

type pbes1Params struct {
	Salt       []uint8
	Iterations int64
}

func DecryptPBES1(encrypted []byte) ([]byte, error) {
	var info encryptedPrivateKeyInfo
	_, err := asn1.Unmarshal(encrypted, &info)
	if err != nil {
		return nil, err
	}

	var pbeParams pbes1Params
	_, err = asn1.Unmarshal(info.EncryptionAlgorithm.Parameters.FullBytes, &pbeParams)
	if err != nil {
		panic(err)
	}

	var md hash.Hash
	if info.EncryptionAlgorithm.Algorithm.Equal(oidPBEMD5DESCBC) {
		md = md5.New()
	} else if info.EncryptionAlgorithm.Algorithm.Equal(oidPBEMD5RC2CBC) {
		md = md5.New()
	} else if info.EncryptionAlgorithm.Algorithm.Equal(oidPBESHA1DESCBC) {
		md = sha1.New()
	} else if info.EncryptionAlgorithm.Algorithm.Equal(oidPBESHA1RC2CBC) {
		md = sha1.New()
	}

	keyIv, err := pbkdf1([]byte("1f56fd979f58464a7c9082b4d093f403"), pbeParams.Salt, 16, int(pbeParams.Iterations), md)
	if err != nil {
		panic(err)
	}

	key := keyIv[:8]
	iv := keyIv[8:]

	var cb cipher.Block
	if info.EncryptionAlgorithm.Algorithm.Equal(oidPBEMD5DESCBC) {
		cb, err = des.NewCipher(key)
		if err != nil {
			return nil, err
		}
	} else if info.EncryptionAlgorithm.Algorithm.Equal(oidPBEMD5RC2CBC) {
		cb, err = NewRC2(key, 64)
		if err != nil {
			return nil, err
		}
	} else if info.EncryptionAlgorithm.Algorithm.Equal(oidPBESHA1DESCBC) {
		cb, err = des.NewCipher(key)
		if err != nil {
			return nil, err
		}
	} else if info.EncryptionAlgorithm.Algorithm.Equal(oidPBESHA1RC2CBC) {
		cb, err = NewRC2(key, 64)
		if err != nil {
			return nil, err
		}
	}

	dst := make([]byte, len(info.EncryptedData))
	bm := cipher.NewCBCDecrypter(cb, iv)
	bm.CryptBlocks(dst, info.EncryptedData)

	return dst[:len(dst)-(int)(dst[len(dst)-1])], nil
}
