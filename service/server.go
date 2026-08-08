package service

import (
	"net/http"
	"time"
)

const (
	readHeaderTimeout = 5 * time.Second
	readTimeout       = 30 * time.Second
	writeTimeout      = 30 * time.Second
	idleTimeout       = 2 * time.Minute
	maxHeaderBytes    = 1 << 20
)

func NewHTTPServer(listenAddress string) *http.Server {
	return &http.Server{
		Addr:              listenAddress,
		Handler:           NewRouter(),
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
		MaxHeaderBytes:    maxHeaderBytes,
	}
}

// StartServer creates and initializes the server api
func StartServer(listenAddress string) error {
	return NewHTTPServer(listenAddress).ListenAndServe()
}
