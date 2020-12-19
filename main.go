package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/adi/sketo/api"
	"github.com/adi/sketo/metrics"
	"github.com/adi/sketo/util"
)

func main() {
	test := flag.Bool("test", false, "Adds one million documents")
	flag.Parse()

	if test != nil && *test == true {
		api.Test()
		os.Exit(0)
	}
	log.Printf("Starting...")
	ctx, cancel := context.WithCancel(context.Background())

	wg := &sync.WaitGroup{}

	var err error

	// Start metrics server
	metricsMux := util.StartHTTPServer(ctx, wg, "Metrics Server", ":9104")
	err = metrics.Init(metricsMux)
	if err != nil {
		log.Panicf("Couldn't initialize Metrics Server: %v", err)
	}

	// Start sketo API server
	apiMux := util.StartHTTPServer(ctx, wg, "API Server", ":4466")
	err = api.Init(apiMux)
	if err != nil {
		log.Panicf("Couldn't initialize API Server: %v", err)
	}

	log.Printf("Started")

	// React properly to signals
	sg := make(chan os.Signal)
	signal.Notify(sg, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	for {
		select {
		case signal := <-sg:
			switch signal {
			case syscall.SIGINT, syscall.SIGTERM:
				log.Printf("Received signal=%s. Allowing HTTP servers to gracefully shut down...", signal.String())
				cancel()
				wg.Wait()
				log.Printf("Exiting")
				os.Exit(0)
			case syscall.SIGHUP:
				log.Printf("Reload config triggered by signal=%s", signal.String())
			}
		}
	}
}
