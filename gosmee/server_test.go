package gosmee

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/urfave/cli/v2"
	"gotest.tools/v3/assert"
)

type relayFunc func(ctx context.Context, channel string, data []byte) (string, error)

func (f relayFunc) Publish(ctx context.Context, channel string, data []byte) (string, error) {
	return f(ctx, channel, data)
}

func TestEventBroker(t *testing.T) {
	t.Run("Subscribe and Publish", func(t *testing.T) {
		eb := NewEventBroker()

		// Subscribe to a channel
		channel := "test-channel"
		subscriber := eb.Subscribe(channel, nil)

		// Verify subscriber was added
		assert.Equal(t, subscriber.Channel, channel)
		assert.Assert(t, subscriber.Events != nil, "Events channel should not be nil")
		assert.Equal(t, len(eb.subscribers[channel]), 1)

		// Publish a message
		testData := []byte(`{"test":"data"}`)
		eb.Publish(channel, testData)

		// Verify subscriber received the message
		receivedData := <-subscriber.Events
		assert.DeepEqual(t, receivedData.Data, testData)

		// Unsubscribe
		eb.Unsubscribe(channel, subscriber)

		// Verify subscriber was removed
		_, ok := eb.subscribers[channel]
		assert.Assert(t, !ok, "channel state should be removed when the last subscriber unsubscribes")

		// Verify channel was closed (this would panic if not closed properly)
		_, isOpen := <-subscriber.Events
		assert.Assert(t, !isOpen, "Channel should be closed after unsubscribing")
	})

	t.Run("Multiple Subscribers", func(t *testing.T) {
		eb := NewEventBroker()
		channel := "test-channel"

		// Create multiple subscribers
		sub1 := eb.Subscribe(channel, nil)
		sub2 := eb.Subscribe(channel, nil)

		// Verify both were added
		assert.Equal(t, len(eb.subscribers[channel]), 2)

		// Publish a message
		testData := []byte(`{"test":"data"}`)
		eb.Publish(channel, testData)

		// Verify both received the message
		assert.DeepEqual(t, (<-sub1.Events).Data, testData)
		assert.DeepEqual(t, (<-sub2.Events).Data, testData)

		// Unsubscribe one
		eb.Unsubscribe(channel, sub1)

		// Verify only sub1 was removed
		assert.Equal(t, len(eb.subscribers[channel]), 1)

		// Publish another message
		testData2 := []byte(`{"test":"data2"}`)
		eb.Publish(channel, testData2)

		// Verify only sub2 received it
		assert.DeepEqual(t, (<-sub2.Events).Data, testData2)
	})

	t.Run("Encrypted Subscribers Receive Ciphertext", func(t *testing.T) {
		eb := NewEventBroker()
		channel := "secret-channel"

		plaintextSubscriber := eb.Subscribe(channel, nil)

		eb.Publish(channel, []byte(`{"test":"public"}`))
		assert.DeepEqual(t, (<-plaintextSubscriber.Events).Data, []byte(`{"test":"public"}`))

		publicKey, privateKey, err := GenerateKeyPair()
		assert.NilError(t, err)

		encryptedSubscriber := eb.Subscribe(channel, publicKey)

		testData := []byte(`{"test":"secret"}`)
		eb.Publish(channel, testData)

		assert.DeepEqual(t, (<-plaintextSubscriber.Events).Data, testData)

		receivedEncrypted := <-encryptedSubscriber.Events
		assert.Assert(t, IsEncrypted(receivedEncrypted.Data))

		decrypted, err := Decrypt(receivedEncrypted.Data, privateKey)
		assert.NilError(t, err)
		assert.DeepEqual(t, decrypted, testData)
	})
}

func TestEventBrokerPrefixSubscriptions(t *testing.T) {
	drain := func(t *testing.T, subscriber *Subscriber) []string {
		t.Helper()

		var received []string
		for {
			select {
			case event := <-subscriber.Events:
				received = append(received, string(event.Data))
			default:
				return received
			}
		}
	}

	t.Run("a prefix subscriber receives its whole subtree", func(t *testing.T) {
		eb := NewEventBroker()
		subscriber := eb.SubscribePrefix("a", nil)
		defer eb.Unsubscribe("a", subscriber)

		assert.Equal(t, subscriber.Channel, "a")
		assert.Assert(t, subscriber.Prefix)

		for _, channel := range []string{"a", "a/b", "a/b/c", "ab", "abc/x", "b", "b/a"} {
			eb.Publish(channel, []byte(channel))
		}

		assert.DeepEqual(t, drain(t, subscriber), []string{"a", "a/b", "a/b/c"})
	})

	t.Run("a root prefix subscriber receives everything", func(t *testing.T) {
		eb := NewEventBroker()
		subscriber := eb.SubscribePrefix("", nil)
		defer eb.Unsubscribe("", subscriber)

		for _, channel := range []string{"a", "a/b", "zzz", "other/deep/path"} {
			eb.Publish(channel, []byte(channel))
		}

		assert.DeepEqual(t, drain(t, subscriber), []string{"a", "a/b", "zzz", "other/deep/path"})
	})

	t.Run("an exact subscriber still only receives its own channel", func(t *testing.T) {
		eb := NewEventBroker()
		subscriber := eb.Subscribe("a", nil)
		defer eb.Unsubscribe("a", subscriber)

		assert.Assert(t, !subscriber.Prefix)

		eb.Publish("a/b", []byte("a/b"))
		eb.Publish("a", []byte("a"))

		assert.DeepEqual(t, drain(t, subscriber), []string{"a"})
	})

	t.Run("exact and prefix subscribers on the same channel each get one copy", func(t *testing.T) {
		eb := NewEventBroker()
		exact := eb.Subscribe("a", nil)
		defer eb.Unsubscribe("a", exact)
		prefix := eb.SubscribePrefix("a", nil)
		defer eb.Unsubscribe("a", prefix)

		eb.Publish("a", []byte("a"))

		assert.DeepEqual(t, drain(t, exact), []string{"a"})
		assert.DeepEqual(t, drain(t, prefix), []string{"a"})
	})

	t.Run("unsubscribe closes the channel and drops the key", func(t *testing.T) {
		eb := NewEventBroker()
		subscriber := eb.SubscribePrefix("a", nil)

		eb.Lock()
		assert.Equal(t, len(eb.prefixSubscribers["a"]), 1)
		eb.Unlock()

		eb.Unsubscribe("a", subscriber)

		eb.Lock()
		_, ok := eb.prefixSubscribers["a"]
		eb.Unlock()
		assert.Assert(t, !ok, "prefix state should be removed when the last subscriber unsubscribes")

		_, isOpen := <-subscriber.Events
		assert.Assert(t, !isOpen, "Channel should be closed after unsubscribing")
	})

	t.Run("a prefix subscriber with a public key receives ciphertext", func(t *testing.T) {
		eb := NewEventBroker()
		publicKey, privateKey, err := GenerateKeyPair()
		assert.NilError(t, err)

		subscriber := eb.SubscribePrefix("a", publicKey)
		defer eb.Unsubscribe("a", subscriber)

		eb.Publish("a/b", []byte(`{"secret":true}`))

		event := <-subscriber.Events
		assert.Assert(t, IsEncrypted(event.Data))
		decrypted, err := Decrypt(event.Data, privateKey)
		assert.NilError(t, err)
		assert.DeepEqual(t, decrypted, []byte(`{"secret":true}`))
	})
}

func TestWebhookSignatureValidation(t *testing.T) {
	t.Run("GitHub Signature", func(t *testing.T) {
		secret := "test-secret"
		payload := []byte(`{"event":"test"}`)

		// Generate a valid signature
		mac := createGitHubSignature(secret, payload)

		// Test valid signature
		valid := validateGitHubWebhookSignature(secret, payload, "sha256="+mac)
		assert.Assert(t, valid, "Valid signature should be accepted")

		// Test invalid signature
		invalid := validateGitHubWebhookSignature(secret, payload, "sha256=invalid")
		assert.Assert(t, !invalid, "Invalid signature should be rejected")

		// Test invalid format
		invalidFormat := validateGitHubWebhookSignature(secret, payload, "invalid-format")
		assert.Assert(t, !invalidFormat, "Invalid format should be rejected")
	})

	t.Run("Bitbucket HMAC", func(t *testing.T) {
		secret := "test-secret"
		payload := []byte(`{"event":"test"}`)

		// Create valid signature
		mac := createBitbucketSignature(secret, payload)

		// Test valid signature
		valid := validateBitbucketHMAC(secret, payload, mac)
		assert.Assert(t, valid, "Valid signature should be accepted")

		// Test invalid signature
		invalid := validateBitbucketHMAC(secret, payload, "invalid")
		assert.Assert(t, !invalid, "Invalid signature should be rejected")
	})

	t.Run("Gitea Signature", func(t *testing.T) {
		secret := "test-secret"
		payload := []byte(`{"event":"test"}`)

		// Create valid signature
		mac := createGiteaSignature(secret, payload)

		// Test valid signature
		valid := validateGiteaSignature(secret, payload, "sha256="+mac)
		assert.Assert(t, valid, "Valid signature should be accepted")

		// Test invalid signature
		invalid := validateGiteaSignature(secret, payload, "sha256=invalid")
		assert.Assert(t, !invalid, "Invalid signature should be rejected")

		// Test invalid format
		invalidFormat := validateGiteaSignature(secret, payload, "invalid-format")
		assert.Assert(t, !invalidFormat, "Invalid format should be rejected")
	})

	t.Run("Validate Multiple Providers", func(t *testing.T) {
		secrets := []string{"secret1", "secret2"}
		payload := []byte(`{"event":"test"}`)

		// GitHub header
		r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/webhook", nil)
		r.Header.Set("X-Hub-Signature-256", "sha256="+createGitHubSignature("secret1", payload))
		valid := validateWebhookSignature(secrets, payload, r)
		assert.Assert(t, valid, "Valid GitHub signature should be accepted")

		// Bitbucket header
		r = httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/webhook", nil)
		r.Header.Set("X-Hub-Signature", createBitbucketSignature("secret2", payload))
		valid = validateWebhookSignature(secrets, payload, r)
		assert.Assert(t, valid, "Valid Bitbucket signature should be accepted")

		// GitLab token
		r = httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/webhook", nil)
		r.Header.Set("X-Gitlab-Token", "secret1")
		valid = validateWebhookSignature(secrets, payload, r)
		assert.Assert(t, valid, "Valid GitLab token should be accepted")

		// Gitea signature
		r = httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/webhook", nil)
		r.Header.Set("X-Gitea-Signature", "sha256="+createGiteaSignature("secret2", payload))
		valid = validateWebhookSignature(secrets, payload, r)
		assert.Assert(t, valid, "Valid Gitea signature should be accepted")

		// No secrets provided
		valid = validateWebhookSignature([]string{}, payload, r)
		assert.Assert(t, valid, "No secrets should always return true")

		// Invalid signatures
		r = httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/webhook", nil)
		r.Header.Set("X-Hub-Signature-256", "sha256=invalid")
		valid = validateWebhookSignature(secrets, payload, r)
		assert.Assert(t, !valid, "Invalid signature should be rejected")
	})
}

func newTestContext() *cli.Context {
	app := cli.NewApp()
	flagSet := flag.NewFlagSet("test", 0)
	flagSet.Int("max-body-size", 26214400, "doc")
	flagSet.String("replay-token", "", "doc")
	return cli.NewContext(app, flagSet, nil)
}

func TestHandleWebhookPost(t *testing.T) {
	// Set up router, SSE server, and event broker
	router := chi.NewRouter()
	eventBroker := NewEventBroker()
	relay := newLocalPayloadRelay(eventBroker)
	ctx := newTestContext()

	// Set up the webhook endpoint
	router.Post(channelPath, handleWebhookPost(ctx, relay, []string{}))

	t.Run("Valid Webhook", func(t *testing.T) {
		// Create a subscriber to verify event was published
		subscriber := eventBroker.Subscribe("test-channel", nil)

		// Create a test request
		payload := map[string]any{
			"event": "test",
			"data":  "value",
		}
		payloadBytes, _ := json.Marshal(payload)
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/webhook/test-channel", bytes.NewReader(payloadBytes))
		req.Header.Set("Content-Type", contentType)
		req.Header.Set("X-Event-Type", "test-event")

		// Record the response
		w := httptest.NewRecorder()

		// Route the request
		// Set up URL parameters since we're not using the full router
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("*", "test-channel")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		handler := handleWebhookPost(ctx, relay, []string{})
		handler(w, req)

		// Check response
		resp := w.Result()
		assert.Equal(t, resp.StatusCode, http.StatusAccepted)

		// Check that the event was published
		select {
		case event := <-subscriber.Events:
			// Verify the event data contains our payload
			assert.Assert(t, len(event.Data) > 0)

			// Parse the event and check key fields
			var eventData map[string]any
			err := json.Unmarshal(event.Data, &eventData)
			assert.NilError(t, err)

			// Check that headers were properly set
			assert.Equal(t, eventData["x-event-type"], "test-event")

			// Check that the body was base64 encoded
			assert.Assert(t, eventData["bodyB"] != nil)

			// Check that timestamp was added
			assert.Assert(t, eventData["timestamp"] != nil)
		default:
			t.Fatal("Expected event to be published but none was received")
		}

		// Clean up
		eventBroker.Unsubscribe("test-channel", subscriber)
	})

	t.Run("Unconfigured Channel Stays Plaintext", func(t *testing.T) {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/webhook/unknown-channel", strings.NewReader(`{"ok":true}`))
		req.Header.Set("Content-Type", contentType)

		w := httptest.NewRecorder()

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("*", "unknown-channel")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		handler := handleWebhookPost(ctx, relay, []string{})
		handler(w, req)

		resp := w.Result()
		assert.Equal(t, resp.StatusCode, http.StatusAccepted)
	})

	t.Run("Invalid Content Type", func(t *testing.T) {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/webhook/test-channel", strings.NewReader("not json"))
		req.Header.Set("Content-Type", "text/plain")

		w := httptest.NewRecorder()

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("*", "test-channel")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		handler := handleWebhookPost(ctx, relay, []string{})
		handler(w, req)

		resp := w.Result()
		assert.Equal(t, resp.StatusCode, http.StatusBadRequest)

		body, _ := io.ReadAll(resp.Body)
		assert.Assert(t, strings.Contains(string(body), "content-type must be application/json"))
	})

	t.Run("Invalid JSON", func(t *testing.T) {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/webhook/test-channel", strings.NewReader("not json"))
		req.Header.Set("Content-Type", contentType)

		w := httptest.NewRecorder()

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("*", "test-channel")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		handler := handleWebhookPost(ctx, relay, []string{})
		handler(w, req)

		resp := w.Result()
		assert.Equal(t, resp.StatusCode, http.StatusBadRequest)
	})

	t.Run("Signature Validation", func(t *testing.T) {
		secrets := []string{"test-secret"}
		payload := []byte(`{"event":"test"}`)

		// Valid signature
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/webhook/test-channel", bytes.NewReader(payload))
		req.Header.Set("Content-Type", contentType)
		req.Header.Set("X-Hub-Signature-256", "sha256="+createGitHubSignature("test-secret", payload))

		w := httptest.NewRecorder()

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("*", "test-channel")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		handler := handleWebhookPost(ctx, relay, secrets)
		handler(w, req)

		resp := w.Result()
		assert.Equal(t, resp.StatusCode, http.StatusAccepted)

		// Invalid signature
		req = httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/webhook/test-channel", bytes.NewReader(payload))
		req.Header.Set("Content-Type", contentType)
		req.Header.Set("X-Hub-Signature-256", "sha256=invalid")

		w = httptest.NewRecorder()

		rctx = chi.NewRouteContext()
		rctx.URLParams.Add("*", "test-channel")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		handler = handleWebhookPost(ctx, relay, secrets)
		handler(w, req)

		resp = w.Result()
		assert.Equal(t, resp.StatusCode, http.StatusUnauthorized)
	})
}

func TestHandleWebhookPostRelay(t *testing.T) {
	t.Run("Shared Relay Delivers To Another Server Instance", func(t *testing.T) {
		ctx := newTestContext()
		brokerA := NewEventBroker()
		localA := newLocalPayloadRelay(brokerA)

		brokerB := NewEventBroker()
		localB := newLocalPayloadRelay(brokerB)
		subscriberB := brokerB.Subscribe("test-channel", nil)
		defer brokerB.Unsubscribe("test-channel", subscriberB)

		sharedRelay := relayFunc(func(ctx context.Context, channel string, data []byte) (string, error) {
			if _, err := localA.Publish(ctx, channel, data); err != nil {
				return "", err
			}
			return localB.Publish(ctx, channel, data)
		})

		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/webhook/test-channel", strings.NewReader(`{"event":"test"}`))
		req.Header.Set("Content-Type", contentType)
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("*", "test-channel")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		w := httptest.NewRecorder()
		handleWebhookPost(ctx, sharedRelay, []string{})(w, req)

		assert.Equal(t, w.Result().StatusCode, http.StatusAccepted)
		select {
		case event := <-subscriberB.Events:
			assert.Assert(t, len(event.Data) > 0)
		default:
			t.Fatal("Expected event to be delivered to subscriber on another server instance")
		}
	})

	t.Run("Shared Publish Error Returns Server Error", func(t *testing.T) {
		ctx := newTestContext()
		failingRelay := relayFunc(func(context.Context, string, []byte) (string, error) {
			return "", errors.New("redis unavailable")
		})

		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/webhook/test-channel", strings.NewReader(`{"event":"test"}`))
		req.Header.Set("Content-Type", contentType)
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("*", "test-channel")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		w := httptest.NewRecorder()
		handleWebhookPost(ctx, failingRelay, []string{})(w, req)

		resp := w.Result()
		assert.Equal(t, resp.StatusCode, http.StatusInternalServerError)
		body, err := io.ReadAll(resp.Body)
		assert.NilError(t, err)
		assert.Assert(t, strings.Contains(string(body), "publish event: redis unavailable"))
	})
}

func TestHandleReplayPost(t *testing.T) {
	makeReplayRequest := func(t *testing.T, replayToken, authHeader string) *httptest.ResponseRecorder {
		t.Helper()

		eventBroker := NewEventBroker()
		relay := newLocalPayloadRelay(eventBroker)
		subscriber := eventBroker.Subscribe("test-channel", nil)
		defer eventBroker.Unsubscribe("test-channel", subscriber)

		ctx := newTestContext()
		assert.NilError(t, ctx.Set("replay-token", replayToken))

		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/replay/test-channel", strings.NewReader(`{"event":"replay"}`))
		req.Header.Set("Content-Type", contentType)
		if authHeader != "" {
			req.Header.Set("Authorization", authHeader)
		}

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("*", "test-channel")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		w := httptest.NewRecorder()
		handler := handleReplayPost(ctx, relay)
		handler(w, req)

		if w.Code == http.StatusAccepted {
			select {
			case event := <-subscriber.Events:
				var eventData map[string]any
				err := json.Unmarshal(event.Data, &eventData)
				assert.NilError(t, err)
				assert.Assert(t, eventData["authorization"] == nil)
			default:
				t.Fatal("Expected event to be published but none was received")
			}
		}

		return w
	}

	t.Run("No token configured and no auth header returns accepted", func(t *testing.T) {
		resp := makeReplayRequest(t, "", "")
		assert.Equal(t, resp.Code, http.StatusAccepted)
	})

	t.Run("Token configured and correct bearer auth returns accepted", func(t *testing.T) {
		resp := makeReplayRequest(t, "test-replay-token", "Bearer test-replay-token")
		assert.Equal(t, resp.Code, http.StatusAccepted)
	})

	t.Run("Token configured and wrong bearer auth returns unauthorized", func(t *testing.T) {
		resp := makeReplayRequest(t, "test-replay-token", "Bearer wrong-token")
		assert.Equal(t, resp.Code, http.StatusUnauthorized)
	})

	t.Run("Token configured and missing auth header returns unauthorized", func(t *testing.T) {
		resp := makeReplayRequest(t, "test-replay-token", "")
		assert.Equal(t, resp.Code, http.StatusUnauthorized)
	})

	t.Run("Token configured and malformed auth header returns unauthorized", func(t *testing.T) {
		resp := makeReplayRequest(t, "test-replay-token", "Basic xxx")
		assert.Equal(t, resp.Code, http.StatusUnauthorized)
	})

	t.Run("Shared Publish Error Returns Server Error", func(t *testing.T) {
		ctx := newTestContext()
		failingRelay := relayFunc(func(context.Context, string, []byte) (string, error) {
			return "", errors.New("redis unavailable")
		})

		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/replay/test-channel", strings.NewReader(`{"event":"replay"}`))
		req.Header.Set("Content-Type", contentType)
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("*", "test-channel")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		w := httptest.NewRecorder()
		handleReplayPost(ctx, failingRelay)(w, req)

		resp := w.Result()
		assert.Equal(t, resp.StatusCode, http.StatusInternalServerError)
		body, err := io.ReadAll(resp.Body)
		assert.NilError(t, err)
		assert.Assert(t, strings.Contains(string(body), "publish replay event: redis unavailable"))
	})
}

func TestHandleEventsGet(t *testing.T) {
	eventBroker := NewEventBroker()
	allowedKey := mustGeneratePublicKey(t)
	protectedChannels := mustProtectedChannels(t, map[string][]string{
		"test-channel": {allowedKey},
	})
	router := chi.NewRouter()
	router.Get(eventsPath, handleEventsGet(eventBroker, protectedChannels, "*", false))

	t.Run("Rejects Invalid Public Key", func(t *testing.T) {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/events/test-channel?pubkey=!!!", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, w.Result().StatusCode, http.StatusNotFound)
	})

	t.Run("Rejects Missing Public Key", func(t *testing.T) {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/events/test-channel", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, w.Result().StatusCode, http.StatusNotFound)
	})

	t.Run("Allows Plaintext Subscriber On Unprotected Channel", func(t *testing.T) {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/events/plain-channel", nil)
		reqCtx, cancel := context.WithCancel(req.Context())
		req = req.WithContext(reqCtx)
		defer cancel()

		response := httptest.NewRecorder()
		done := make(chan struct{})
		go func() {
			router.ServeHTTP(response, req)
			close(done)
		}()

		assert.Assert(t, eventually(t, func() bool {
			eventBroker.RLock()
			defer eventBroker.RUnlock()
			return len(eventBroker.subscribers["plain-channel"]) == 1
		}))

		eventBroker.Publish("plain-channel", []byte(`{"plain":true}`))

		assert.Assert(t, eventually(t, func() bool {
			return strings.Contains(response.Body.String(), `{"plain":true}`)
		}))

		body := response.Body.String()
		assert.Assert(t, strings.Contains(body, `{"message":"connected"}`))
		assert.Assert(t, strings.Contains(body, `{"message":"ready"}`))
		assert.Assert(t, strings.Contains(body, `{"plain":true}`))
		assert.Assert(t, !strings.Contains(body, `"ciphertext"`))

		cancel()
		<-done
	})

	t.Run("Allows Unprotected Channel Even With PubKey Query", func(t *testing.T) {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/events/unknown-channel?pubkey="+url.QueryEscape(allowedKey), nil)
		reqCtx, cancel := context.WithCancel(req.Context())
		req = req.WithContext(reqCtx)
		defer cancel()

		response := httptest.NewRecorder()
		done := make(chan struct{})
		go func() {
			router.ServeHTTP(response, req)
			close(done)
		}()

		assert.Assert(t, eventually(t, func() bool {
			eventBroker.RLock()
			defer eventBroker.RUnlock()
			return len(eventBroker.subscribers["unknown-channel"]) == 1
		}))

		eventBroker.Publish("unknown-channel", []byte(`{"plain":true}`))
		assert.Assert(t, eventually(t, func() bool {
			return strings.Contains(response.Body.String(), `{"plain":true}`)
		}))
		assert.Assert(t, !strings.Contains(response.Body.String(), `"ciphertext"`))

		cancel()
		<-done
	})

	t.Run("Allows Authorized Subscriber", func(t *testing.T) {
		publicKey, privateKey, err := GenerateKeyPair()
		assert.NilError(t, err)
		allowed := EncodePublicKey(publicKey)

		protectedChannels = mustProtectedChannels(t, map[string][]string{
			"test-channel": {allowed},
		})
		router = chi.NewRouter()
		router.Get(eventsPath, handleEventsGet(eventBroker, protectedChannels, "*", false))

		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/events/test-channel?pubkey="+url.QueryEscape(allowed), nil)
		reqCtx, cancel := context.WithCancel(req.Context())
		req = req.WithContext(reqCtx)
		defer cancel()

		response := httptest.NewRecorder()
		done := make(chan struct{})
		go func() {
			router.ServeHTTP(response, req)
			close(done)
		}()

		assert.Assert(t, eventually(t, func() bool {
			eventBroker.RLock()
			defer eventBroker.RUnlock()
			return len(eventBroker.subscribers["test-channel"]) == 1
		}))

		eventBroker.Publish("test-channel", []byte(`{"secret":true}`))

		assert.Assert(t, eventually(t, func() bool {
			return strings.Contains(response.Body.String(), `"ciphertext"`)
		}))

		body := response.Body.String()
		assert.Assert(t, strings.Contains(body, `{"message":"connected"}`))
		assert.Assert(t, strings.Contains(body, `{"message":"ready"}`))

		parts := strings.Split(body, "data: ")
		lastData := strings.TrimSpace(parts[len(parts)-1])
		decrypted, err := Decrypt([]byte(lastData), privateKey)
		assert.NilError(t, err)
		assert.DeepEqual(t, decrypted, []byte(`{"secret":true}`))

		cancel()
		<-done
	})
}

// authorizeEventSubscriber writes its own rejections, so drive it through a
// real chi router and report what it authorized instead of blocking on SSE.
func authorizeProbeRouter(protectedChannels *ProtectedChannels, allowOpenRoot bool) *chi.Mux {
	router := chi.NewRouter()
	router.Get(eventsPath, func(w http.ResponseWriter, r *http.Request) {
		sub, ok := authorizeEventSubscriber(w, r, protectedChannels, allowOpenRoot)
		if !ok {
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"channel": sub.Channel,
			"prefix":  sub.Prefix,
			"hasKey":  sub.PubKey != nil,
		})
	})
	return router
}

func TestAuthorizeEventSubscriberPrefix(t *testing.T) {
	subscriberKey := mustGeneratePublicKey(t)
	otherKey := mustGeneratePublicKey(t)

	get := func(t *testing.T, router *chi.Mux, path string) *httptest.ResponseRecorder {
		t.Helper()

		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet, path, nil))
		return w
	}

	assertAuthorized := func(t *testing.T, w *httptest.ResponseRecorder, channel string, prefix, hasKey bool) {
		t.Helper()

		assert.Equal(t, w.Code, http.StatusOK)
		var got map[string]any
		assert.NilError(t, json.Unmarshal(w.Body.Bytes(), &got))
		assert.Equal(t, got["channel"], channel)
		assert.Equal(t, got["prefix"], prefix)
		assert.Equal(t, got["hasKey"], hasKey)
	}

	openChannels, err := LoadProtectedChannels("")
	assert.NilError(t, err)

	t.Run("no prefix parameter keeps exact mode", func(t *testing.T) {
		assertAuthorized(t, get(t, authorizeProbeRouter(openChannels, false), "/events/abc"), "abc", false, false)
	})

	t.Run("prefix mode on an unprotected subtree needs no key", func(t *testing.T) {
		assertAuthorized(t, get(t, authorizeProbeRouter(openChannels, false), "/events/abc?prefix=1"), "abc", true, false)
	})

	t.Run("root subscription is gated unless explicitly opened", func(t *testing.T) {
		assert.Equal(t, get(t, authorizeProbeRouter(openChannels, false), "/events/?prefix=1").Code, http.StatusNotFound)
		assertAuthorized(t, get(t, authorizeProbeRouter(openChannels, true), "/events/?prefix=1"), "", true, false)
	})

	t.Run("wildcard entry authorizes the root for its key", func(t *testing.T) {
		wildcardChannels := mustProtectedChannels(t, map[string][]string{
			"*": {subscriberKey},
		})
		router := authorizeProbeRouter(wildcardChannels, false)

		assertAuthorized(t, get(t, router, "/events/?prefix=1&pubkey="+url.QueryEscape(subscriberKey)), "", true, true)
		assert.Equal(t, get(t, router, "/events/?prefix=1&pubkey="+url.QueryEscape(otherKey)).Code, http.StatusNotFound)
		assert.Equal(t, get(t, router, "/events/?prefix=1").Code, http.StatusNotFound)
	})

	// The security story: a subtree subscription must be authorized for every
	// protected channel it can observe.
	t.Run("a protected descendant gates the whole subtree", func(t *testing.T) {
		protectedChannels := mustProtectedChannels(t, map[string][]string{
			"abc/secret": {subscriberKey},
		})
		router := authorizeProbeRouter(protectedChannels, false)

		assert.Equal(t, get(t, router, "/events/abc?prefix=1").Code, http.StatusNotFound)
		assert.Equal(t, get(t, router, "/events/abc?prefix=1&pubkey="+url.QueryEscape(otherKey)).Code, http.StatusNotFound)
		assertAuthorized(t, get(t, router, "/events/abc?prefix=1&pubkey="+url.QueryEscape(subscriberKey)), "abc", true, true)
	})

	t.Run("a delegated descendant is not unlocked by the parent key", func(t *testing.T) {
		protectedChannels := mustProtectedChannels(t, map[string][]string{
			"abc":        {subscriberKey},
			"abc/secret": {otherKey},
		})
		router := authorizeProbeRouter(protectedChannels, false)

		assert.Equal(t, get(t, router, "/events/abc?prefix=1&pubkey="+url.QueryEscape(subscriberKey)).Code, http.StatusNotFound)
		assertAuthorized(t, get(t, router, "/events/abc/secret?prefix=1&pubkey="+url.QueryEscape(otherKey)), "abc/secret", true, true)
	})

	// A protected entry covers its subtree, so an exact subscription below it
	// cannot be used to walk around the prefix gate.
	t.Run("exact mode honors ancestor protection", func(t *testing.T) {
		protectedChannels := mustProtectedChannels(t, map[string][]string{
			"abc": {subscriberKey},
		})
		router := authorizeProbeRouter(protectedChannels, false)

		assert.Equal(t, get(t, router, "/events/abc/secret").Code, http.StatusNotFound)
		assertAuthorized(t, get(t, router, "/events/abc/secret?pubkey="+url.QueryEscape(subscriberKey)), "abc/secret", false, true)
	})

	// Behavior kept from before prefix mode: on an unprotected channel an
	// unparseable pubkey is ignored rather than rejected.
	t.Run("exact mode still ignores a bad key on an unprotected channel", func(t *testing.T) {
		assertAuthorized(t, get(t, authorizeProbeRouter(openChannels, false), "/events/abc?pubkey=!!!"), "abc", false, false)
	})

	t.Run("invalid requests are rejected", func(t *testing.T) {
		router := authorizeProbeRouter(openChannels, false)

		assert.Equal(t, get(t, router, "/events/abc?prefix=notabool").Code, http.StatusBadRequest)
		assert.Equal(t, get(t, router, "/events/abc?prefix=").Code, http.StatusBadRequest)
		assert.Equal(t, get(t, router, "/events/has.dot?prefix=1").Code, http.StatusBadRequest)
		assert.Equal(t, get(t, router, "/events/?prefix=1&pubkey=!!!").Code, http.StatusNotFound)
	})
}

func TestHandleEventsGetPrefixSubscription(t *testing.T) {
	eventBroker := NewEventBroker()
	protectedChannels, err := LoadProtectedChannels("")
	assert.NilError(t, err)
	router := chi.NewRouter()
	router.Get(eventsPath, handleEventsGet(eventBroker, protectedChannels, "*", false))

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/events/team?prefix=1", nil)
	reqCtx, cancel := context.WithCancel(req.Context())
	req = req.WithContext(reqCtx)
	defer cancel()

	response := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		router.ServeHTTP(response, req)
		close(done)
	}()

	assert.Assert(t, eventually(t, func() bool {
		eventBroker.RLock()
		defer eventBroker.RUnlock()
		return len(eventBroker.prefixSubscribers["team"]) == 1
	}))

	eventBroker.Publish("team/github/push", []byte(`{"subtree":true}`))

	assert.Assert(t, eventually(t, func() bool {
		return strings.Contains(response.Body.String(), `{"subtree":true}`)
	}))
	// Without this header a client cannot tell an old server from one that
	// honored the request.
	assert.Equal(t, response.Header().Get("X-Gosmee-Subscription"), "prefix")

	cancel()
	<-done
}

func TestHandleEventsGetCORSOrigin(t *testing.T) {
	testCases := []struct {
		name           string
		corsOrigin     string
		expectedHeader string
		expectPresent  bool
	}{
		{
			name:           "Wildcard Origin",
			corsOrigin:     "*",
			expectedHeader: "*",
			expectPresent:  true,
		},
		{
			name:           "Specific Origin",
			corsOrigin:     "https://example.com",
			expectedHeader: "https://example.com",
			expectPresent:  true,
		},
		{
			name:          "Empty Origin Omits Header",
			corsOrigin:    "",
			expectPresent: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			eventBroker := NewEventBroker()
			protectedChannels, err := LoadProtectedChannels("")
			assert.NilError(t, err)
			router := chi.NewRouter()
			router.Get(eventsPath, handleEventsGet(eventBroker, protectedChannels, tc.corsOrigin, false))

			req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/events/plainchannel1", nil)
			reqCtx, cancel := context.WithCancel(req.Context())
			req = req.WithContext(reqCtx)
			defer cancel()

			response := httptest.NewRecorder()
			done := make(chan struct{})
			go func() {
				router.ServeHTTP(response, req)
				close(done)
			}()

			assert.Assert(t, eventually(t, func() bool {
				return strings.Contains(response.Body.String(), `{"message":"connected"}`)
			}))

			headerValue := response.Header().Get("Access-Control-Allow-Origin")
			if tc.expectPresent {
				assert.Equal(t, headerValue, tc.expectedHeader)
			} else {
				assert.Equal(t, headerValue, "")
			}

			cancel()
			<-done
		})
	}
}

func TestServeIndexAndNewURL(t *testing.T) {
	protectedChannels := mustProtectedChannels(t, map[string][]string{
		"protectedchan": {mustGeneratePublicKey(t)},
	})

	t.Run("root redirects to a plaintext channel", func(t *testing.T) {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
		w := httptest.NewRecorder()

		handler := serveIndex("https://example.com", "", protectedChannels)
		handler(w, req)

		resp := w.Result()
		assert.Equal(t, resp.StatusCode, http.StatusFound)
		location := resp.Header.Get("Location")
		assert.Assert(t, strings.HasPrefix(location, "https://example.com/"))
		assert.Assert(t, !strings.HasSuffix(location, "/protectedchan"))
	})

	t.Run("plaintext channel page is rendered", func(t *testing.T) {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/plainchannel1", nil)
		w := httptest.NewRecorder()

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("*", "plainchannel1")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		handler := serveIndex("https://example.com", "footer text", protectedChannels)
		handler(w, req)

		resp := w.Result()
		assert.Equal(t, resp.StatusCode, http.StatusOK)
		body, err := io.ReadAll(resp.Body)
		assert.NilError(t, err)
		bodyStr := string(body)
		assert.Assert(t, strings.Contains(bodyStr, "plainchannel1"))
		// html/template contextually escapes JS strings, so "/" is rendered as `\/` in script blocks.
		assert.Assert(t, strings.Contains(bodyStr, "/events/plainchannel1") || strings.Contains(bodyStr, "\\/events\\/plainchannel1"))
	})

	t.Run("protected channel page is hidden", func(t *testing.T) {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/protectedchan", nil)
		w := httptest.NewRecorder()

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("*", "protectedchan")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		handler := serveIndex("https://example.com", "", protectedChannels)
		handler(w, req)

		assert.Equal(t, w.Result().StatusCode, http.StatusNotFound)
	})

	t.Run("new endpoint avoids protected channels", func(t *testing.T) {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/new", nil)
		w := httptest.NewRecorder()

		handler := showNewURL("https://example.com", protectedChannels)
		handler(w, req)

		resp := w.Result()
		assert.Equal(t, resp.StatusCode, http.StatusOK)
		body, err := io.ReadAll(resp.Body)
		assert.NilError(t, err)
		assert.Assert(t, strings.HasPrefix(strings.TrimSpace(string(body)), "https://example.com/"))
		assert.Assert(t, !strings.Contains(string(body), "protectedchan"))
	})

	// A protected entry now protects its whole subtree, so a page below it must
	// stay hidden too.
	t.Run("channel under a protected prefix is hidden", func(t *testing.T) {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/protectedchan/github/push", nil)
		w := httptest.NewRecorder()

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("*", "protectedchan/github/push")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		handler := serveIndex("https://example.com", "", protectedChannels)
		handler(w, req)

		assert.Equal(t, w.Result().StatusCode, http.StatusNotFound)
	})

	t.Run("wildcard entry leaves no public channel to hand out", func(t *testing.T) {
		wildcardChannels := mustProtectedChannels(t, map[string][]string{
			"*": {mustGeneratePublicKey(t)},
		})

		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/new", nil)
		w := httptest.NewRecorder()
		showNewURL("https://example.com", wildcardChannels)(w, req)
		assert.Equal(t, w.Result().StatusCode, http.StatusNotFound)

		req = httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
		w = httptest.NewRecorder()
		serveIndex("https://example.com", "", wildcardChannels)(w, req)
		assert.Equal(t, w.Result().StatusCode, http.StatusNotFound)
	})
}

// A "*" entry covers every candidate, so the generator must give up instead of
// looping forever.
func TestNextPlaintextChannelWithWildcard(t *testing.T) {
	wildcardChannels := mustProtectedChannels(t, map[string][]string{
		"*": {mustGeneratePublicKey(t)},
	})

	done := make(chan struct{})
	var channel string
	var ok bool
	go func() {
		defer close(done)
		channel, ok = nextPlaintextChannel(wildcardChannels)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("nextPlaintextChannel hung on a wildcard protected-channels config")
	}
	assert.Assert(t, !ok)
	assert.Equal(t, channel, "")

	plain, ok := nextPlaintextChannel(mustProtectedChannels(t, map[string][]string{
		"protectedchan": {mustGeneratePublicKey(t)},
	}))
	assert.Assert(t, ok)
	assert.Equal(t, len(plain), minChannelLength)
}

func TestEffectivePublicURL(t *testing.T) {
	t.Run("returns explicit public URL unchanged", func(t *testing.T) {
		assert.Equal(t, effectivePublicURL("https://hooks.example.com", "localhost:3333", false), "https://hooks.example.com")
	})

	t.Run("defaults to http address when tls is disabled", func(t *testing.T) {
		assert.Equal(t, effectivePublicURL("", "localhost:3333", false), "http://localhost:3333")
	})

	t.Run("defaults to https address when tls is enabled", func(t *testing.T) {
		assert.Equal(t, effectivePublicURL("", "localhost:3333", true), "https://localhost:3333")
	})
}

func TestRetVersion(t *testing.T) {
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/version", nil)
	w := httptest.NewRecorder()

	retVersion(w, req)

	resp := w.Result()
	assert.Equal(t, resp.StatusCode, http.StatusOK)
	assert.Equal(t, resp.Header.Get("Content-Type"), contentType)
	assert.Equal(t, resp.Header.Get(versionHeaderName), strings.TrimSpace(string(Version)))

	// Verify JSON response
	body, _ := io.ReadAll(resp.Body)
	var response map[string]string
	err := json.Unmarshal(body, &response)
	assert.NilError(t, err)
	assert.Equal(t, response["version"], strings.TrimSpace(string(Version)))
}

func TestIPRestrictions(t *testing.T) {
	t.Run("Parse IP Ranges", func(t *testing.T) {
		ranges := []string{
			"192.168.0.0/24",
			"10.0.0.1",
			"2001:db8::/32",
		}

		ipRanges, err := parseIPRanges(ranges)
		assert.NilError(t, err)
		assert.Equal(t, len(ipRanges.networks), 2)
		assert.Equal(t, len(ipRanges.ips), 1)

		// Test valid IPs
		assert.Assert(t, ipRanges.contains(net.ParseIP("192.168.0.100")))
		assert.Assert(t, ipRanges.contains(net.ParseIP("10.0.0.1")))
		assert.Assert(t, ipRanges.contains(net.ParseIP("2001:db8::1")))

		// Test invalid IPs
		assert.Assert(t, !ipRanges.contains(net.ParseIP("192.168.1.1")))
		assert.Assert(t, !ipRanges.contains(net.ParseIP("10.0.0.2")))
		assert.Assert(t, !ipRanges.contains(net.ParseIP("2001:db9::1")))

		// Test invalid ranges
		_, err = parseIPRanges([]string{"invalid"})
		assert.Assert(t, err != nil)
	})

	t.Run("Get Real IP", func(t *testing.T) {
		// Test direct IP
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
		req.RemoteAddr = "192.168.0.1:12345"

		ip, err := getRealIP(req, false)
		assert.NilError(t, err)
		assert.Equal(t, ip.String(), "192.168.0.1")

		// Test X-Forwarded-For with trust proxy
		req = httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
		req.RemoteAddr = "127.0.0.1:12345"
		req.Header.Set("X-Forwarded-For", "10.0.0.1")

		ip, err = getRealIP(req, true)
		assert.NilError(t, err)
		assert.Equal(t, ip.String(), "10.0.0.1")

		// Test X-Forwarded-For without trust proxy
		ip, err = getRealIP(req, false)
		assert.NilError(t, err)
		assert.Equal(t, ip.String(), "127.0.0.1")

		// Test invalid remote addr
		req = httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
		req.RemoteAddr = "invalid"

		_, err = getRealIP(req, false)
		assert.Assert(t, err != nil)
	})

	t.Run("IP Restrict Middleware", func(t *testing.T) {
		// Create allowed IP ranges that include the test IP
		ranges, _ := parseIPRanges([]string{"127.0.0.0/8"})
		middleware := ipRestrictMiddleware(ranges, false)

		// Create a test handler
		nextCalled := false
		next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			nextCalled = true
			w.WriteHeader(http.StatusOK)
		})

		// Test allowed IP with POST request (IP restriction is only applied to POST requests)
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/", nil) // Changed from GET to POST
		req.RemoteAddr = "127.0.0.1:12345"
		w := httptest.NewRecorder()

		middleware(next).ServeHTTP(w, req)
		assert.Assert(t, nextCalled, "Next handler should be called for allowed IP")
		assert.Equal(t, w.Result().StatusCode, http.StatusOK)

		// Test disallowed IP with POST request
		nextCalled = false
		req = httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/", nil) // Changed from GET to POST
		req.RemoteAddr = "192.168.0.1:12345"
		w = httptest.NewRecorder()

		middleware(next).ServeHTTP(w, req)
		assert.Assert(t, !nextCalled, "Next handler should not be called for disallowed IP")
		assert.Equal(t, w.Result().StatusCode, http.StatusForbidden)

		// Test that GET request bypasses IP restriction
		nextCalled = false
		req = httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
		req.RemoteAddr = "192.168.0.1:12345" // IP would be restricted for POST
		w = httptest.NewRecorder()

		middleware(next).ServeHTTP(w, req)
		assert.Assert(t, nextCalled, "Next handler should be called for GET request regardless of IP")
		assert.Equal(t, w.Result().StatusCode, http.StatusOK)
	})
}

// Helper functions to create signatures for testing

func createGitHubSignature(secret string, payload []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}

func createBitbucketSignature(secret string, payload []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}

func createGiteaSignature(secret string, payload []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}

func eventually(t *testing.T, predicate func() bool) bool {
	t.Helper()

	for range 50 {
		if predicate() {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}

	return false
}

func mustGeneratePublicKey(t *testing.T) string {
	t.Helper()

	publicKey, _, err := GenerateKeyPair()
	assert.NilError(t, err)
	return EncodePublicKey(publicKey)
}

func mustProtectedChannels(t *testing.T, channels map[string][]string) *ProtectedChannels {
	t.Helper()

	cfg := protectedChannelsFile{
		Channels: make(map[string]protectedChannelConfig, len(channels)),
	}
	for channel, allowedKeys := range channels {
		cfg.Channels[channel] = protectedChannelConfig{AllowedPublicKeys: allowedKeys}
	}

	data, err := json.Marshal(cfg)
	assert.NilError(t, err)

	path := t.TempDir() + "/channels.json"
	assert.NilError(t, os.WriteFile(path, data, 0o600))

	protectedChannels, err := LoadProtectedChannels(path)
	assert.NilError(t, err)
	return protectedChannels
}

func TestHandleWebhookPostPublishesChannel(t *testing.T) {
	var published map[string]any
	relay := relayFunc(func(_ context.Context, _ string, data []byte) (string, error) {
		return "", json.Unmarshal(data, &published)
	})

	router := chi.NewRouter()
	router.Post(channelPath, handleWebhookPost(newTestContext(), relay, nil))

	post := func(t *testing.T, target string, headers map[string]string) {
		t.Helper()
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, target, strings.NewReader(`{"a":1}`))
		req.Header.Set("Content-Type", contentType)
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assert.Equal(t, w.Code, http.StatusAccepted)
	}

	t.Run("payload carries the channel", func(t *testing.T) {
		post(t, "/team/github/push", nil)
		assert.Equal(t, published["x-gosmee-channel"], "team/github/push")
	})

	t.Run("a spoofed header does not win", func(t *testing.T) {
		post(t, "/team/github/push", map[string]string{"X-Gosmee-Channel": "evil"})
		assert.Equal(t, published["x-gosmee-channel"], "team/github/push")
	})
}

func TestHandleReplayPostPublishesChannel(t *testing.T) {
	var published map[string]any
	relay := relayFunc(func(_ context.Context, _ string, data []byte) (string, error) {
		return "", json.Unmarshal(data, &published)
	})

	router := chi.NewRouter()
	router.Post(replayPath, handleReplayPost(newTestContext(), relay))

	post := func(t *testing.T, headers map[string]string) {
		t.Helper()
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/replay/team/github/push", strings.NewReader(`{"a":1}`))
		req.Header.Set("Content-Type", contentType)
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assert.Equal(t, w.Code, http.StatusAccepted)
	}

	t.Run("payload carries the channel", func(t *testing.T) {
		post(t, nil)
		assert.Equal(t, published["x-gosmee-channel"], "team/github/push")
	})

	t.Run("a spoofed header does not win", func(t *testing.T) {
		post(t, map[string]string{"X-Gosmee-Channel": "evil"})
		assert.Equal(t, published["x-gosmee-channel"], "team/github/push")
	})
}
