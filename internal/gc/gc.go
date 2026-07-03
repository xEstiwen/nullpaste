package gc

import (
	"log"
	"time"

	"nullpaste/internal/store"
)

func Start(s store.Store, interval time.Duration, done <-chan struct{}) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			n, err := s.Sweep(time.Now())
			if err != nil {
				log.Printf("gc sweep error: %v", err)
				continue
			}
			if n > 0 {
				log.Printf("gc: deleted %d expired paste(s)", n)
			}
		case <-done:
			return
		}
	}
}
