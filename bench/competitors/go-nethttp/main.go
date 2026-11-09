// Go net/http with its defaults (GOMAXPROCS = CPUs), HTTP/1.1 and h2c on one port (Go 1.24+
// serves unencrypted HTTP/2 natively when Protocols allows it).
package main

import (
	"bytes"
	"crypto/tls"
	"io"
	"net/http"
	"os"
	"time"
)

var hello = []byte("Hello, World!")
var b64k = bytes.Repeat([]byte("x"), 64*1024)
var b1m = bytes.Repeat([]byte("x"), 1024*1024)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write(hello)
	})
	mux.HandleFunc("GET /64k", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write(b64k)
	})
	mux.HandleFunc("GET /1m", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write(b1m)
	})
	mux.HandleFunc("POST /echo", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.Copy(w, r.Body)
	})
	var p http.Protocols
	p.SetHTTP1(true)
	p.SetUnencryptedHTTP2(true)
	srv := &http.Server{Addr: ":" + port, Handler: mux, Protocols: &p, IdleTimeout: 120 * time.Second}
	// TLS 1.3 on 8443 with ALPN h2 and http/1.1 when the bench certificate exists
	if _, err := os.Stat("/opt/bench/cert/cert.pem"); err == nil {
		ts := &http.Server{Addr: ":8443", Handler: mux, IdleTimeout: 120 * time.Second, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13}}
		go func() {
			if err := ts.ListenAndServeTLS("/opt/bench/cert/cert.pem", "/opt/bench/cert/key.pem"); err != nil {
				panic(err)
			}
		}()
	}
	if err := srv.ListenAndServe(); err != nil {
		panic(err)
	}
}
