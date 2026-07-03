package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"nullpaste/internal/config"
	"nullpaste/internal/server"
	"nullpaste/internal/store"
)

func main() {
	cfg := config.Load()
	flag.Parse()

	db, err := store.New(cfg.DBPath)
	if err != nil {
		log.Fatalf("db open: %v", err)
	}
	defer db.Close()

	srv := server.New(cfg, db)

	done := make(chan os.Signal, 1)
	signal.Notify(done, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-done
		log.Println("shutting down...")
		srv.Shutdown()
		os.Exit(0)
	}()

	log.Printf("listening on %s", cfg.Addr)
	if err := http.ListenAndServe(cfg.Addr, srv); err != nil {
		log.Fatalf("listen: %v", err)
	}
}
