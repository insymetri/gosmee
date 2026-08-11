package gosmee

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"gotest.tools/v3/assert"
)

// TestPrefixSubscriptionEndToEnd runs the real server routes and the real SSE
// client against each other, so it proves that the wire protocol, the channel
// propagation and the target rewrite compose.
func TestPrefixSubscriptionEndToEnd(t *testing.T) {
	eventBroker := NewEventBroker()
	relay := newLocalPayloadRelay(eventBroker)

	mainRouter := chi.NewRouter()
	registerMainRoutes(mainRouter, "https://example.com", "", nil, handleEventsGet(eventBroker, nil, "*", true))

	restrictedRouter := chi.NewRouter()
	restrictedRouter.Post(channelPath, handleWebhookPost(newTestContext(), relay, nil))

	finalRouter := chi.NewRouter()
	finalRouter.Mount("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			restrictedRouter.ServeHTTP(w, r)
			return
		}
		mainRouter.ServeHTTP(w, r)
	}))

	gosmeeServer := httptest.NewServer(finalRouter)
	defer gosmeeServer.Close()

	var mu sync.Mutex
	var gotPaths []string
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotPaths = append(gotPaths, r.URL.Path)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	sub, err := prepareSubscription(gosmeeServer.URL+"/team", "", true)
	assert.NilError(t, err)
	assert.Equal(t, sub.Channel, "team")
	assert.Assert(t, sub.Prefix)

	gs := newTestGoSmeeForProcessing(&replayDataOpts{
		smeeURL:       gosmeeServer.URL + "/team",
		targetURL:     target.URL,
		channelPrefix: sub.Channel,
		prefixMode:    true,
	})
	gs.logger = slog.New(slog.DiscardHandler)

	ctx, cancel := context.WithCancel(context.Background())
	clientDone := make(chan error, 1)
	go func() {
		clientDone <- gs.runSSEClient(ctx, sub.SSEURL, "test", nil)
	}()

	// The broker only delivers to subscribers that are already registered.
	eventually(t, func() bool {
		eventBroker.RLock()
		defer eventBroker.RUnlock()
		return len(eventBroker.prefixSubscribers["team"]) == 1
	})

	post := func(path string) {
		t.Helper()
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, gosmeeServer.URL+path, strings.NewReader(`{"hello":"world"}`))
		assert.NilError(t, err)
		req.Header.Set("Content-Type", contentType)
		resp, err := gosmeeServer.Client().Do(req)
		assert.NilError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, resp.StatusCode, http.StatusAccepted)
	}

	post("/team/github/push")
	eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(gotPaths) == 1
	})

	post("/team")
	eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(gotPaths) == 2
	})

	mu.Lock()
	assert.DeepEqual(t, gotPaths, []string{"/github/push", "/"})
	mu.Unlock()

	cancel()
	select {
	case err := <-clientDone:
		assert.Assert(t, err != nil)
		assert.Equal(t, err, context.Canceled)
	case <-time.After(5 * time.Second):
		t.Fatal("the SSE client did not shut down after the context was canceled")
	}
}
