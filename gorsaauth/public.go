package gorsaauth

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
)

func NewPublicKey(data []byte) (*PublicKey, error) {
	k := PublicKey{len: defaultTokenLength}
	parsedKey, err := x509.ParsePKIXPublicKey(data)
	if err != nil {
		return nil, err
	}
	k.key = parsedKey.(*rsa.PublicKey)
	return &k, nil
}

func (k PublicKey) AuthHex(hexToken string) (*SignedToken, error) {
	if data, err := hex.DecodeString(hexToken); err != nil {
		return nil, err
	} else {
		return k.Auth(data)
	}
}
func (k PublicKey) Auth(data []byte) (*SignedToken, error) {
	token := SignedToken{
		data: make([]byte, k.len),
		sign: make([]byte, 512),
	}

	buff := bytes.NewBuffer(data)
	buff.Read(token.data)
	buff.Read(token.sign)
	if err := k.Verify(token.data, token.sign); err != nil {
		return nil, err
	}
	return &token, nil
}

func (k PublicKey) Verify(data []byte, sign []byte) error {
	h := sha512.New()
	h.Write(data)
	digest := h.Sum(nil)
	return rsa.VerifyPKCS1v15(k.key, crypto.SHA512, digest, sign)
}
