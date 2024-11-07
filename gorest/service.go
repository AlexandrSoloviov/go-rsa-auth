package gorest

import (
	"fmt"
	"log"
	"net/http"
)

type Service struct {
	auth_header string
	port        int
	server      http.Server
	mux         http.ServeMux
	Sessions    *ServiceSessions
}

func New(port int) *Service {
	s := Service{
		auth_header: "X-SERVICE-AUTH",
		port:        port,
		server:      http.Server{},
		mux:         *http.NewServeMux(),
		Sessions:    newServiceSessions(),
	}
	s.server.Addr = fmt.Sprintf(":%d", port)
	s.server.Handler = &s.mux
	return &s
}

// Установить имя заголовка для авторизации
func (s *Service) SetAuthHeaderName(name string) {
	s.auth_header = name
}

// Установить таймаут сессии
func (s *Service) SetTimeout(n int) {
	s.Sessions.Timeout = n
}

func (s *Service) AuthHandle(path string, handler http.HandlerFunc) {
	s.mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		if err := s.authHttp(r); err != nil {
			w.WriteHeader(403)
			w.Write([]byte("ACCESS DENY"))
			log.Println("ACCESS DENY", err)
			return
		}
		handler(w, r)
	})
}

func (s *Service) Handle(path string, handler http.HandlerFunc) {
	s.mux.HandleFunc(path, handler)
}

func (s *Service) Run() error {
	return s.server.ListenAndServe()
}
