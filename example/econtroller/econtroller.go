package econtroller

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/AlexandrSoloviov/go-rsa-auth/gorest"
	"github.com/AlexandrSoloviov/go-rsa-auth/gorsaauth"
)

type Controller struct {
	auth         *gorsaauth.PublicKey
	sessions     *gorest.ServiceSessions
	errorMessage string
}

type authResponse struct {
	SessionToken string
	ExpiredAt    time.Time
	Timeout      int
}

func (c *Controller) SetKey(k *gorsaauth.PublicKey) {
	c.auth = k
}

func (c *Controller) SetErrorMessage(message string) {
	c.errorMessage = message
}

func NewController(ss *gorest.ServiceSessions) *Controller {
	c := Controller{
		sessions: ss,
	}
	return &c
}

type authRequest struct {
	Token string `json:"token` // Авторизационный токен
}

func (c *Controller) Auth(w http.ResponseWriter, r *http.Request) {
	request, err := gorest.GetRequest[authRequest](r)
	if err != nil {
		w.WriteHeader(400)
		w.Write([]byte("ERROR.1002"))
		log.Println("ERROR:", err)
		return
	}
	token, err := c.auth.AuthHex(request.Token)
	if err != nil {
		w.WriteHeader(403)
		w.Write([]byte("ERROR.1003"))
		log.Println("ERROR:", err)
		return
	}
	sessionToken, err := c.sessions.Auth(token.ExpiredAt())
	if err != nil {
		w.WriteHeader(400)
		w.Write([]byte("ERROR.1004"))
		log.Println("ERROR:", err)
		return
	}
	response, err := json.Marshal(authResponse{
		SessionToken: fmt.Sprintf("%x", sessionToken),
		ExpiredAt:    token.ExpiredAt(),
		Timeout:      c.sessions.Timeout,
	})
	if err != nil {
		w.WriteHeader(400)
		w.Write([]byte("ERROR.1005"))
		log.Println("ERROR:", err)
		return
	}
	w.Write(response)
}

func (c *Controller) Work(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("WORK DONE\n"))
}
