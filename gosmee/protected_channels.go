package gosmee

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

type protectedChannelsFile struct {
	Channels map[string]protectedChannelConfig `json:"channels"`
}

type protectedChannelConfig struct {
	AllowedPublicKeys []string `json:"allowed_public_keys"`
}

// rootChannelEntry is the configuration spelling of the root prefix. It is
// normalized to the internal key "" at load time, which makes it the ancestor
// of every channel and lets the longest-prefix lookups treat it like any other
// entry.
const rootChannelEntry = "*"

type ProtectedChannels struct {
	channels map[string]map[string]struct{}
}

func LoadProtectedChannels(path string) (*ProtectedChannels, error) {
	if path == "" {
		return &ProtectedChannels{
			channels: make(map[string]map[string]struct{}),
		}, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg protectedChannelsFile
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("unmarshal encrypted channels file: %w", err)
	}
	if len(cfg.Channels) == 0 {
		return nil, fmt.Errorf("encrypted channels file must define at least one channel")
	}

	protected := &ProtectedChannels{
		channels: make(map[string]map[string]struct{}, len(cfg.Channels)),
	}

	for channel, channelCfg := range cfg.Channels {
		if channel == "" {
			return nil, fmt.Errorf("encrypted channels file contains an empty channel id")
		}
		if channel == rootChannelEntry {
			channel = ""
		}
		if channel != "" && !isValidChannelID(channel) {
			return nil, fmt.Errorf("encrypted channel %q must match %q", channel, channelIDPattern)
		}
		if len(channelCfg.AllowedPublicKeys) == 0 {
			return nil, fmt.Errorf("encrypted channel %q must define at least one allowed public key", channel)
		}

		allowed := make(map[string]struct{}, len(channelCfg.AllowedPublicKeys))
		for _, encodedKey := range channelCfg.AllowedPublicKeys {
			publicKey, err := ParsePublicKey(encodedKey)
			if err != nil {
				return nil, fmt.Errorf("invalid public key for channel %q: %w", channel, err)
			}
			allowed[EncodePublicKey(publicKey)] = struct{}{}
		}

		protected.channels[channel] = allowed
	}

	return protected, nil
}

func (p *ProtectedChannels) Has(channel string) bool {
	if p == nil {
		return false
	}

	_, ok := p.channels[channel]
	return ok
}

// nearestEntry returns the allowed keys of the closest protecting entry for
// channel: the entry on channel itself, else on its nearest protected ancestor.
// An entry protects its whole subtree, so only the nearest one applies.
func (p *ProtectedChannels) nearestEntry(channel string) (map[string]struct{}, bool) {
	if p == nil {
		return nil, false
	}

	var allowedKeys map[string]struct{}
	var found bool
	forEachChannelAncestor(channel, func(prefix string) bool {
		allowedKeys, found = p.channels[prefix]
		return !found
	})
	return allowedKeys, found
}

// Covers reports whether channel is protected, either by an entry on itself or
// by an entry on one of its ancestors.
func (p *ProtectedChannels) Covers(channel string) bool {
	_, ok := p.nearestEntry(channel)
	return ok
}

// CoversRoot reports whether the whole server is protected by a "*" entry.
func (p *ProtectedChannels) CoversRoot() bool {
	if p == nil {
		return false
	}

	_, ok := p.channels[""]
	return ok
}

// HasProtectedDescendant reports whether a protected entry lives strictly below
// prefix.
func (p *ProtectedChannels) HasProtectedDescendant(prefix string) bool {
	if p == nil {
		return false
	}

	for channel := range p.channels {
		if channel == prefix {
			continue
		}
		if prefix == "" || strings.HasPrefix(channel, prefix+"/") {
			return true
		}
	}
	return false
}

// AllowsSubtree reports whether publicKey is allowed on every protected entry
// at or below prefix. A subtree subscriber sees every channel below prefix, so
// it must hold the key to all of them. It is vacuously true when nothing below
// prefix is protected.
func (p *ProtectedChannels) AllowsSubtree(prefix string, publicKey *[32]byte) bool {
	if p == nil {
		return true
	}

	var encodedKey string
	if publicKey != nil {
		encodedKey = EncodePublicKey(publicKey)
	}
	for channel, allowedKeys := range p.channels {
		if channel != prefix && prefix != "" && !strings.HasPrefix(channel, prefix+"/") {
			continue
		}
		if publicKey == nil {
			return false
		}
		if _, ok := allowedKeys[encodedKey]; !ok {
			return false
		}
	}
	return true
}

func (p *ProtectedChannels) IsAllowed(channel string, publicKey *[32]byte) bool {
	if p == nil || publicKey == nil {
		return false
	}

	allowedKeys, ok := p.nearestEntry(channel)
	if !ok {
		return false
	}

	_, ok = allowedKeys[EncodePublicKey(publicKey)]
	return ok
}
