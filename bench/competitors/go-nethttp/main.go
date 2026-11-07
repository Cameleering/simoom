// Go net/http with its defaults (GOMAXPROCS = CPUs), HTTP/1.1 and h2c on one port (Go 1.24+
// serves unencrypted HTTP/2 natively when Protocols allows it).
package main

import (
	"io"
	"net/http"
	"os"
	"time"
)

var hello = []byte("Hello, World!")

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
	mux.HandleFunc("POST /echo", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.Copy(w, r.Body)
	})
	var p http.Protocols
	p.SetHTTP1(true)
	p.SetUnencryptedHTTP2(true)
	srv := &http.Server{Addr: ":" + port, Handler: mux, Protocols: &p, IdleTimeout: 120 * time.Second}
	if err := srv.ListenAndServe(); err != nil {
		panic(err)
	}
}
