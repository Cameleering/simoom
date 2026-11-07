// fasthttp with the settings its README recommends for throughput: no header normalization
// work beyond the defaults, no Date header caching changes, GOMAXPROCS = CPUs, and SO_REUSEPORT
// listeners (one per CPU) through fasthttp's reuseport package, as in its TechEmpower entry.
package main

import (
	"os"
	"runtime"

	"github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/reuseport"
)

var hello = []byte("Hello, World!")

func handler(ctx *fasthttp.RequestCtx) {
	if ctx.IsPost() {
		ctx.SetContentType("application/json")
		ctx.SetBody(ctx.PostBody())
		return
	}
	ctx.SetContentType("text/plain")
	ctx.SetBody(hello)
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	s := &fasthttp.Server{Handler: handler, Name: "fasthttp", Concurrency: 1 << 20, NoDefaultServerHeader: false}
	n := runtime.GOMAXPROCS(0)
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		ln, err := reuseport.Listen("tcp4", "0.0.0.0:"+port)
		if err != nil {
			panic(err)
		}
		go func() { errs <- s.Serve(ln) }()
	}
	panic(<-errs)
}
