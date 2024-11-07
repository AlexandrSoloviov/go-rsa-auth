package gorest

import (
	"bytes"
	"encoding/hex"
	"errors"
	"log"
	"net/http"
)

func (s *Service) authHttp(r *http.Request) error {
	str_token := r.Header.Get(s.auth_header)
	if str_token == "" {
		return errors.New("NO_AUTH_HEADER_IN_REQUEST")
	}
	_token, err := hex.DecodeString(str_token)
	if err != nil {
		return err
	}
	buff := bytes.NewBuffer(_token)
	token := make([]byte, 128)
	digest := make([]byte, 32)

	if n, err := buff.Read(token); err != nil {
		log.Println("Error in read token")
		return err
	} else if n < 128 {
		return errors.New("SHORT_TOKEN")
	}
	if n, err := buff.Read(digest); err != nil {
		log.Println("Error in read digest")
		return err
	} else if n < 32 {
		return errors.New("SHORT_DIGEST")
	}
	_digest := s.Sessions.Hmac(token)
	if bytes.Equal(_digest, digest) {
		return errors.New("BAD_TOKEN_DIGEST")
	}
	session := s.Sessions.Get(token)
	if session == nil {
		return errors.New("SESSION_NOT_EXISTS")
	}
	return nil
}
