package gorest

import (
	"encoding/json"
	"io"
	"net/http"
)

func GetRequest[RequestType any](r *http.Request) (*RequestType, error) {
	xxx := make([]RequestType, 1)
	req := xxx[0]
	body, err := io.ReadAll(r.Body)

	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal(body, &req); err != nil {
		return nil, err
	}
	return &req, nil
}
