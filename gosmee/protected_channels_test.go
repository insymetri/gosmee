package gosmee

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"gotest.tools/v3/assert"
)

func TestLoadProtectedChannels(t *testing.T) {
	t.Run("empty path disables protected channels", func(t *testing.T) {
		protectedChannels, err := LoadProtectedChannels("")
		assert.NilError(t, err)
		assert.Assert(t, !protectedChannels.Has("test-channel"))
	})

	t.Run("valid config", func(t *testing.T) {
		publicKey, _, err := GenerateKeyPair()
		assert.NilError(t, err)

		cfg := protectedChannelsFile{
			Channels: map[string]protectedChannelConfig{
				"test-channel": {
					AllowedPublicKeys: []string{EncodePublicKey(publicKey)},
				},
			},
		}

		data, err := json.Marshal(cfg)
		assert.NilError(t, err)

		path := filepath.Join(t.TempDir(), "channels.json")
		assert.NilError(t, os.WriteFile(path, data, 0o600))

		protectedChannels, err := LoadProtectedChannels(path)
		assert.NilError(t, err)
		assert.Assert(t, protectedChannels.Has("test-channel"))
		assert.Assert(t, protectedChannels.IsAllowed("test-channel", publicKey))
	})

	t.Run("invalid public key", func(t *testing.T) {
		cfg := protectedChannelsFile{
			Channels: map[string]protectedChannelConfig{
				"test-channel": {
					AllowedPublicKeys: []string{"not-a-key"},
				},
			},
		}

		data, err := json.Marshal(cfg)
		assert.NilError(t, err)

		path := filepath.Join(t.TempDir(), "channels.json")
		assert.NilError(t, os.WriteFile(path, data, 0o600))

		_, err = LoadProtectedChannels(path)
		assert.Assert(t, err != nil)
	})

	t.Run("multi segment channel id", func(t *testing.T) {
		publicKey, _, err := GenerateKeyPair()
		assert.NilError(t, err)

		cfg := protectedChannelsFile{
			Channels: map[string]protectedChannelConfig{
				"github/myorg/myrepo/push": {
					AllowedPublicKeys: []string{EncodePublicKey(publicKey)},
				},
			},
		}

		data, err := json.Marshal(cfg)
		assert.NilError(t, err)

		path := filepath.Join(t.TempDir(), "channels.json")
		assert.NilError(t, os.WriteFile(path, data, 0o600))

		protectedChannels, err := LoadProtectedChannels(path)
		assert.NilError(t, err)
		assert.Assert(t, protectedChannels.Has("github/myorg/myrepo/push"))
		assert.Assert(t, protectedChannels.IsAllowed("github/myorg/myrepo/push", publicKey))
	})

	t.Run("wildcard root entry is accepted", func(t *testing.T) {
		publicKey, _, err := GenerateKeyPair()
		assert.NilError(t, err)

		protectedChannels := mustProtectedChannels(t, map[string][]string{
			"*": {EncodePublicKey(publicKey)},
		})
		assert.Assert(t, protectedChannels.CoversRoot())
	})

	t.Run("channel id must match server routes", func(t *testing.T) {
		publicKey, _, err := GenerateKeyPair()
		assert.NilError(t, err)

		for _, channel := range []string{"/leading-slash", "trailing-slash/", "double//slash", "has space", "has.dot", "a/*", "*/a", "**"} {
			cfg := protectedChannelsFile{
				Channels: map[string]protectedChannelConfig{
					channel: {
						AllowedPublicKeys: []string{EncodePublicKey(publicKey)},
					},
				},
			}

			data, err := json.Marshal(cfg)
			assert.NilError(t, err)

			path := filepath.Join(t.TempDir(), "channels.json")
			assert.NilError(t, os.WriteFile(path, data, 0o600))

			_, err = LoadProtectedChannels(path)
			assert.ErrorContains(t, err, `must match`, "channel %q should be rejected", channel)
		}
	})

	t.Run("literal empty channel id is rejected", func(t *testing.T) {
		publicKey, _, err := GenerateKeyPair()
		assert.NilError(t, err)

		cfg := protectedChannelsFile{
			Channels: map[string]protectedChannelConfig{
				"": {AllowedPublicKeys: []string{EncodePublicKey(publicKey)}},
			},
		}
		data, err := json.Marshal(cfg)
		assert.NilError(t, err)

		path := filepath.Join(t.TempDir(), "channels.json")
		assert.NilError(t, os.WriteFile(path, data, 0o600))

		_, err = LoadProtectedChannels(path)
		assert.ErrorContains(t, err, "empty channel id")
	})
}

func TestProtectedChannelsCovers(t *testing.T) {
	protectedChannels := mustProtectedChannels(t, map[string][]string{
		"abc": {mustGeneratePublicKey(t)},
	})

	for _, channel := range []string{"abc", "abc/x", "abc/x/y"} {
		assert.Assert(t, protectedChannels.Covers(channel), "%q should be covered", channel)
	}
	// Coverage follows segment boundaries, never a raw string prefix.
	for _, channel := range []string{"abcd", "abcd/x", "ab", "zzz", ""} {
		assert.Assert(t, !protectedChannels.Covers(channel), "%q should not be covered", channel)
	}
	assert.Assert(t, !protectedChannels.CoversRoot())
}

func TestProtectedChannelsWildcardEntry(t *testing.T) {
	key := mustGeneratePublicKey(t)
	protectedChannels := mustProtectedChannels(t, map[string][]string{
		"*": {key},
	})

	assert.Assert(t, protectedChannels.CoversRoot())
	for _, channel := range []string{"", "a", "a/b"} {
		assert.Assert(t, protectedChannels.Covers(channel), "%q should be covered by the root entry", channel)
	}

	parsedKey, err := ParsePublicKey(key)
	assert.NilError(t, err)
	assert.Assert(t, protectedChannels.IsAllowed("", parsedKey))
	assert.Assert(t, protectedChannels.IsAllowed("a/b", parsedKey))
}

func TestProtectedChannelsLongestMatch(t *testing.T) {
	firstKey := mustGeneratePublicKey(t)
	secondKey := mustGeneratePublicKey(t)
	protectedChannels := mustProtectedChannels(t, map[string][]string{
		"a":   {firstKey},
		"a/b": {secondKey},
	})

	parsedFirst, err := ParsePublicKey(firstKey)
	assert.NilError(t, err)
	parsedSecond, err := ParsePublicKey(secondKey)
	assert.NilError(t, err)

	assert.Assert(t, protectedChannels.IsAllowed("a", parsedFirst))
	assert.Assert(t, protectedChannels.IsAllowed("a/x", parsedFirst))
	// The nearer entry wins outright, so a's key does not unlock a/b's subtree.
	assert.Assert(t, !protectedChannels.IsAllowed("a/b", parsedFirst))
	assert.Assert(t, !protectedChannels.IsAllowed("a/b/c", parsedFirst))
	assert.Assert(t, protectedChannels.IsAllowed("a/b", parsedSecond))
	assert.Assert(t, protectedChannels.IsAllowed("a/b/c", parsedSecond))
	assert.Assert(t, !protectedChannels.IsAllowed("a/x", parsedSecond))
}

func TestProtectedChannelsHasStaysExact(t *testing.T) {
	protectedChannels := mustProtectedChannels(t, map[string][]string{
		"abc": {mustGeneratePublicKey(t)},
	})

	assert.Assert(t, protectedChannels.Has("abc"))
	assert.Assert(t, !protectedChannels.Has("abc/x"))
	assert.Assert(t, !protectedChannels.Has(""))
}

func TestProtectedChannelsSubtreeQueries(t *testing.T) {
	firstKey := mustGeneratePublicKey(t)
	secondKey := mustGeneratePublicKey(t)
	protectedChannels := mustProtectedChannels(t, map[string][]string{
		"a":         {firstKey},
		"a/b":       {secondKey},
		"other/sub": {secondKey},
	})

	parsedFirst, err := ParsePublicKey(firstKey)
	assert.NilError(t, err)
	parsedSecond, err := ParsePublicKey(secondKey)
	assert.NilError(t, err)

	t.Run("HasProtectedDescendant", func(t *testing.T) {
		assert.Assert(t, protectedChannels.HasProtectedDescendant(""))
		assert.Assert(t, protectedChannels.HasProtectedDescendant("a"))
		assert.Assert(t, protectedChannels.HasProtectedDescendant("other"))
		assert.Assert(t, !protectedChannels.HasProtectedDescendant("a/b"))
		assert.Assert(t, !protectedChannels.HasProtectedDescendant("nothing"))
		// Segment boundaries again: "oth" is not an ancestor of "other/sub".
		assert.Assert(t, !protectedChannels.HasProtectedDescendant("oth"))
	})

	t.Run("AllowsSubtree", func(t *testing.T) {
		// firstKey is on "a" but not on "a/b" below it.
		assert.Assert(t, !protectedChannels.AllowsSubtree("a", parsedFirst))
		assert.Assert(t, !protectedChannels.AllowsSubtree("a/b", parsedFirst))
		assert.Assert(t, protectedChannels.AllowsSubtree("a/b", parsedSecond))
		assert.Assert(t, !protectedChannels.AllowsSubtree("", parsedFirst))
		// Vacuously true: nothing protected lives under this prefix.
		assert.Assert(t, protectedChannels.AllowsSubtree("nothing", parsedFirst))
		assert.Assert(t, !protectedChannels.AllowsSubtree("a", nil))
		assert.Assert(t, protectedChannels.AllowsSubtree("nothing", nil))
	})
}
