package gosmee

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"gotest.tools/v3/assert"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	publicKey, privateKey, err := GenerateKeyPair()
	assert.NilError(t, err)

	plaintext := []byte(`{"body":"hello"}`)
	encrypted, err := Encrypt(plaintext, publicKey)
	assert.NilError(t, err)
	assert.Assert(t, IsEncrypted(encrypted))

	decrypted, err := Decrypt(encrypted, privateKey)
	assert.NilError(t, err)
	assert.DeepEqual(t, decrypted, plaintext)
}

func TestDecryptWrongKeyFails(t *testing.T) {
	publicKey, _, err := GenerateKeyPair()
	assert.NilError(t, err)
	_, wrongPrivateKey, err := GenerateKeyPair()
	assert.NilError(t, err)

	encrypted, err := Encrypt([]byte(`{"body":"secret"}`), publicKey)
	assert.NilError(t, err)

	_, err = Decrypt(encrypted, wrongPrivateKey)
	assert.Assert(t, err != nil)
}

func TestIsEncryptedRejectsLookalikePayloads(t *testing.T) {
	assert.Assert(t, !IsEncrypted([]byte(`{"encrypted":true}`)))
	assert.Assert(t, !IsEncrypted([]byte(`{"encrypted":true,"version":99}`)))
	assert.Assert(t, !IsEncrypted([]byte(`{"body":{"encrypted":true}}`)))
}

func TestSaveAndLoadKeyPair(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "keys.json")

	publicKey, privateKey, err := GenerateKeyPair()
	assert.NilError(t, err)
	assert.NilError(t, SaveKeyPair(keyPath, publicKey, privateKey))

	info, err := os.Stat(keyPath)
	assert.NilError(t, err)
	assert.Equal(t, info.Mode().Perm(), os.FileMode(0o600))

	loadedPublicKey, loadedPrivateKey, err := LoadKeyPair(keyPath)
	assert.NilError(t, err)
	assert.DeepEqual(t, loadedPublicKey, publicKey)
	assert.DeepEqual(t, loadedPrivateKey, privateKey)
}

// TestSaveKeyPairWritesParsablePublicKey pins the key file's public_key to the
// encoding the server config and the ?pubkey= parameter accept. Operators copy
// that field into --encrypted-channels-file.
func TestSaveKeyPairWritesParsablePublicKey(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "keys.json")

	publicKey, privateKey, err := GenerateKeyPair()
	assert.NilError(t, err)
	assert.NilError(t, SaveKeyPair(keyPath, publicKey, privateKey))

	data, err := os.ReadFile(keyPath)
	assert.NilError(t, err)
	var stored storedKeyPair
	assert.NilError(t, json.Unmarshal(data, &stored))

	assert.Equal(t, stored.PublicKey, EncodePublicKey(publicKey))

	parsed, err := ParsePublicKey(stored.PublicKey)
	assert.NilError(t, err)
	assert.DeepEqual(t, parsed, publicKey)
}

// TestLoadKeyPairAcceptsLegacyEncoding keeps key files written by an older
// gosmee usable. Those files hold both keys in standard base64.
func TestLoadKeyPairAcceptsLegacyEncoding(t *testing.T) {
	publicKey, privateKey, err := GenerateKeyPair()
	assert.NilError(t, err)

	legacy, err := json.Marshal(storedKeyPair{
		PublicKey:  base64.StdEncoding.EncodeToString(publicKey[:]),
		PrivateKey: base64.StdEncoding.EncodeToString(privateKey[:]),
	})
	assert.NilError(t, err)

	keyPath := filepath.Join(t.TempDir(), "legacy.json")
	assert.NilError(t, os.WriteFile(keyPath, legacy, 0o600))

	loadedPublicKey, loadedPrivateKey, err := LoadKeyPair(keyPath)
	assert.NilError(t, err)
	assert.DeepEqual(t, loadedPublicKey, publicKey)
	assert.DeepEqual(t, loadedPrivateKey, privateKey)
}

func TestDecodeStoredKeyRejectsGarbage(t *testing.T) {
	for _, encoded := range []string{"", "not base64!!", "AAAA"} {
		_, err := decodeStoredKey(encoded)
		assert.Assert(t, err != nil, "expected %q to be rejected", encoded)
	}
}
