package gorsaauth

import (
	"encoding/pem"
	"errors"
	"os"
)

func LoadPem(path string) (*pemFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode(data)
	if len(rest) > 0 {
		return nil, errors.New("MANY_BLOCKS_IN_PEM_FILE")
	}
	pf := pemFile{}
	switch block.Type {
	case "PUBLIC KEY":
		pf.public = block.Bytes
	case "PRIVATE KEY":
		pf.private = block.Bytes
	default:
		return nil, errors.New("BAD_BLOCK_TYPE_IN_PEM_FILE")
	}

	return &pf, nil
}

func (pf pemFile) PublicKey() (*PublicKey, error) {
	if pf.public == nil {
		return nil, errors.New("NO_PUBLIC_KEY_IN_FILE")
	}
	return NewPublicKey(pf.public)
}

func (pf pemFile) PrivateKey() (*PrivateKey, error) {
	if pf.private == nil {
		return nil, errors.New("NO_PRIVATE_KEY_IN_FILE")
	}
	return NewPrivateKey(pf.private)
}
