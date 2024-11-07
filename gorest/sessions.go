package gorest

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"
)

type Session struct {
	timeout   time.Time
	expiredAt time.Time
}

type ServiceSessions struct {
	lock     *sync.Mutex
	Timeout  int
	secret   []byte
	sessions map[string]*Session
}

func newServiceSessions() *ServiceSessions {
	ss := ServiceSessions{
		lock:     &sync.Mutex{},
		Timeout:  60,
		secret:   make([]byte, 128),
		sessions: make(map[string]*Session),
	}
	rand.Read(ss.secret)
	return &ss
}

func (ss *ServiceSessions) Auth(expire time.Time) ([]byte, error) {
	if time.Now().After(expire) {
		return nil, errors.New("AUTH_EXPIRED")
	}
	token := make([]byte, 128)
	rand.Read(token)
	digest := ss.Hmac(token)
	result := bytes.NewBuffer([]byte{})
	result.Write(token)
	result.Write(digest)
	strToken := fmt.Sprintf("%x", token)
	ss.lock.Lock()
	defer ss.lock.Unlock()
	if _, e := ss.sessions[strToken]; e {
		return ss.Auth(expire)
	}
	ss.sessions[strToken] = &Session{
		timeout:   time.Now().Add(time.Duration(ss.Timeout) * time.Second),
		expiredAt: expire,
	}
	return result.Bytes(), nil
}

func (ss ServiceSessions) Hmac(token []byte) []byte {
	hash := hmac.New(sha256.New, ss.secret)
	sum := hash.Sum(token)
	return sum
}

func (ss ServiceSessions) Get(token []byte) *Session {
	ss.lock.Lock()
	defer ss.lock.Unlock()

	strToken := fmt.Sprintf("%x", token)
	if session, e := ss.sessions[strToken]; !e {
		log.Printf("AUTH: session %s not exists in %+v", strToken, ss.sessions)
		return nil
	} else {
		if time.Now().After(session.timeout) {
			log.Printf("AUTH: session %s timeout", strToken)
			delete(ss.sessions, strToken)
			return nil
		}
		if time.Now().After(session.expiredAt) {
			log.Printf("AUTH: session %s expired", strToken)
			delete(ss.sessions, strToken)
			return nil
		}
		session.timeout = time.Now().Add(time.Second * time.Duration(ss.Timeout))
		return session
	}
}
