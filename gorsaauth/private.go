package gorsaauth

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/binary"
	"time"
)

func NewPrivateKey(data []byte) (*PrivateKey, error) {
	k := PrivateKey{
		len: defaultTokenLength,
	}
	parsedKey, err := x509.ParsePKCS8PrivateKey(data)
	if err != nil {
		return nil, err
	}
	k.key = parsedKey.(*rsa.PrivateKey)
	return &k, nil
}

func (rk PrivateKey) Sign(data []byte) ([]byte, error) {
	h := sha512.New()
	h.Write(data)
	digest := h.Sum(nil)
	sign, err := rsa.SignPKCS1v15(rand.Reader, rk.key, crypto.SHA512, digest)
	if err != nil {
		return nil, err
	}
	return sign, nil
}

func (rk PrivateKey) NewToken(ID string, days int) token {
	smt := make([]byte, 0, rk.len*2)
	rnd := make([]byte, rk.len-8-8)
	experationTime := time.Now().Add(time.Hour * time.Duration(24*days))
	now := uint64(experationTime.UnixNano())
	nowBytes := make([]byte, 8)
	rand.Read(rnd)
	id := make([]byte, 8)
	bytes.NewBufferString(ID).Read(id)
	buff := bytes.NewBuffer(smt)
	binary.LittleEndian.PutUint64(nowBytes, now)
	buff.Write(id)
	buff.Write(rnd)
	buff.Write(nowBytes)
	return buff.Bytes()
}

func (t token) Sign(k *PrivateKey) ([]byte, error) {
	buff := bytes.NewBuffer([]byte{})
	buff.Write(t)
	sign, err := k.Sign(t)
	if err != nil {
		return nil, err
	}
	buff.Write(sign)
	return buff.Bytes(), nil
}
