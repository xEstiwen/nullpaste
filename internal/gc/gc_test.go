package gc

import (
	"sync/atomic"
	"testing"
	"time"

	"nullpaste/internal/model"
)

type fakeStore struct {
	sweeps atomic.Int32
}

func (f *fakeStore) Create(*model.Paste) (string, error) { return "", nil }
func (f *fakeStore) Get(string) (*model.Paste, error)    { return nil, nil }
func (f *fakeStore) Delete(string) error                 { return nil }
func (f *fakeStore) Burn(string) (bool, error)           { return false, nil }
func (f *fakeStore) DeleteTokenValid(_, _ string) bool   { return false }
func (f *fakeStore) Close() error                        { return nil }
func (f *fakeStore) Sweep(time.Time) (int, error) {
	f.sweeps.Add(1)
	return 0, nil
}

func TestStartSweepsPeriodicallyAndStops(t *testing.T) {
	fs := &fakeStore{}
	done := make(chan struct{})
	exited := make(chan struct{})
	go func() {
		Start(fs, 5*time.Millisecond, done)
		close(exited)
	}()

	deadline := time.After(2 * time.Second)
	for fs.sweeps.Load() < 2 {
		select {
		case <-deadline:
			t.Fatalf("only %d sweeps within deadline", fs.sweeps.Load())
		case <-time.After(5 * time.Millisecond):
		}
	}

	close(done)
	select {
	case <-exited:
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not return after done was closed")
	}
}
