package util

import (
	"context"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/mux"
)

// StartHTTPServer starts a generic named HTTP Server
func StartHTTPServer(ctx context.Context, wg *sync.WaitGroup, name string, addr string) *mux.Router {

	gorillaMux := mux.NewRouter()

	srvMux := http.NewServeMux()
	srvMux.Handle("/", gorillaMux)

	srv := &http.Server{
		Addr:    addr,
		Handler: srvMux,
	}

	go func() {
		wg.Add(1)
		log.Printf("%s serving on %s\n", name, addr)
		if err := srv.ListenAndServe(); err != http.ErrServerClosed {
			log.Printf("%s ended with error: %v\n", name, err)
		}
		log.Printf("%s exited normally\n", name)
	}()

	go func() {
		for {
			if ctx.Err() == context.Canceled {
				srv.Shutdown(context.Background())
				break
			}
			time.Sleep(1 * time.Second)
		}
		wg.Done()
	}()

	time.Sleep(1 * time.Second)

	return gorillaMux
}
