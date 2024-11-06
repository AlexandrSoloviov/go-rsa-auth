package gorsaauth

import "crypto/rsa"

const defaultTokenLength = 512

type AuthToken struct {
}

type PrivateKey struct {
	len int
	key *rsa.PrivateKey
}

type PublicKey struct {
	len int
	key *rsa.PublicKey
}

type SignedToken struct {
	data []byte
	sign []byte
}

type pemFile struct {
	private []byte
	public  []byte
}

type token []byte
