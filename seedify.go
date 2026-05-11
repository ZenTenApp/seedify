// Copyright (c) 2025-2026 complex (complex@ft.hn)
// See LICENSE for licensing information

// Package seedify provides functions to create seed phrases deterministically
// from an SSH key. This package does not provide functionality to recover
// the original SSH key from the seed phrase.
//
// The purpose of seedify is to generate seed phrases of various lengths
// (12, 15, 16, 18, 21, or 24 words) from an ed25519 private key. These phrases
// can be used for various purposes.
package seedify

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"math"
	"math/big"
	"strings"
	"time"

	"filippo.io/edwards25519"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/bech32"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/chekist32/go-monero/utils"
	polyseed "github.com/complex-gh/polyseed_go"
	"github.com/mr-tron/base58"
	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip06"
	"github.com/nbd-wtf/go-nostr/nip19"
	hdwallet "github.com/stephenlacy/go-ethereum-hdwallet"
	"github.com/tyler-smith/go-bip39"
	"github.com/tyler-smith/go-bip39/wordlists"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/sha3"
)

// Constants for mnemonic generation.
const (
	// wordCountBytesSize is the size in bytes for encoding word count (uint16).
	wordCountBytesSize = 2
	// polyseedWordCount is the word count for polyseed format mnemonics.
	polyseedWordCount = 16
	// bip39MaxWordCount is the maximum word count for BIP39 mnemonics.
	bip39MaxWordCount = 24
	// msPerSecond is the number of milliseconds in one second.
	msPerSecond = 1000

	// PolyseedDefaultBirthday is the default polyseed birthday (1 Jan 2026 00:00 UTC).
	// Using a fixed timestamp ensures deterministic mnemonic output.
	// Pass 0 to use the current time (non-deterministic).
	PolyseedDefaultBirthday = uint64(1767225600)
	// bip32ChainCodeSize is the size in bytes of a BIP32 chain code.
	bip32ChainCodeSize = 32
	// compressedPubKeySize is the size in bytes of a compressed secp256k1 public key (1 prefix + 32 x).
	compressedPubKeySize = 33
)

// entropySizeMap maps word count to entropy size in bytes for BIP39.
//
//nolint:mnd
var entropySizeMap = map[int]int{
	12: 16, // 128 bits
	15: 20, // 160 bits
	18: 24, // 192 bits
	21: 28, // 224 bits
	24: 32, // 256 bits
}

// RSASeedBytes derives a deterministic 32-byte seed from an RSA private key by
// hashing the two secret prime factors with SHA-256: SHA256(P || Q).
// P and Q are the root secrets of an RSA key pair — all other components
// (N, D, Dp, Dq, Qinv) are derived from them.
//
// Returns an error if the key does not have at least two prime factors.
func RSASeedBytes(key *rsa.PrivateKey) ([]byte, error) {
	if len(key.Primes) < 2 { //nolint:mnd
		return nil, fmt.Errorf("RSA key must have at least two prime factors, got %d", len(key.Primes))
	}

	p := key.Primes[0].Bytes()
	q := key.Primes[1].Bytes()

	combined := make([]byte, len(p)+len(q))
	copy(combined, p)
	copy(combined[len(p):], q)

	hash := sha256.Sum256(combined)

	return hash[:], nil
}

// deterministicPrime generates a prime of exactly the given bit length using only
// the provided io.Reader for randomness. It sets the two highest bits to guarantee
// that two such primes multiplied together produce a product of exactly 2×bits
// bits, and sets the lowest bit to ensure the candidate is odd.
//
// Primality is tested with big.Int.ProbablyPrime(0), which applies the
// deterministic Baillie-PSW test and has no known false positives. This avoids
// the non-determinism introduced by big.Int.ProbablyPrime(n>0), which draws
// random Miller-Rabin witnesses from crypto/rand.Reader regardless of the
// caller-provided reader.
func deterministicPrime(prng io.Reader, bits int) (*big.Int, error) {
	if bits < 2 { //nolint:mnd
		return nil, fmt.Errorf("prime size must be at least 2 bits, got %d", bits)
	}

	b := make([]byte, (bits+7)/8) //nolint:mnd
	for {
		if _, err := io.ReadFull(prng, b); err != nil {
			return nil, fmt.Errorf("could not read random bytes: %w", err)
		}

		p := new(big.Int).SetBytes(b)

		// Mask to exactly `bits` bits.
		mask := new(big.Int).Lsh(big.NewInt(1), uint(bits))
		mask.Sub(mask, big.NewInt(1))
		p.And(p, mask)

		// Set the two highest bits so that the product of two such primes has
		// exactly 2×bits bits — identical to the guarantee from crypto/rand.Prime.
		p.SetBit(p, bits-1, 1)
		p.SetBit(p, bits-2, 1) //nolint:mnd

		// Ensure the candidate is odd.
		p.SetBit(p, 0, 1)

		if p.BitLen() == bits && p.ProbablyPrime(0) {
			return p, nil
		}
	}
}

// deterministicReader is an io.Reader backed by an AES-256-CTR stream cipher.
// It produces an infinite, reproducible byte stream from a fixed 32-byte seed,
// making it suitable for deterministic cryptographic key generation.
type deterministicReader struct {
	stream cipher.Stream
}

// Read fills p with deterministic pseudo-random bytes from the AES-CTR stream.
func (r *deterministicReader) Read(p []byte) (int, error) {
	// XOR a zero buffer with the stream to produce the keystream bytes.
	for i := range p {
		p[i] = 0
	}
	r.stream.XORKeyStream(p, p)
	return len(p), nil
}

// newDeterministicReader constructs a deterministicReader using the given 32-byte
// seed as an AES-256 key. The IV is all-zero; the seed must be domain-separated
// by the caller before passing it in.
func newDeterministicReader(seed []byte) (io.Reader, error) {
	block, err := aes.NewCipher(seed)
	if err != nil {
		return nil, fmt.Errorf("could not create AES cipher: %w", err)
	}
	var iv [aes.BlockSize]byte
	stream := cipher.NewCTR(block, iv[:])
	return &deterministicReader{stream: stream}, nil
}

// DeriveEd25519KeyFromRSA deterministically derives an Ed25519 private key from
// an RSA private key. The derivation uses RSASeedBytes (SHA256 of the prime
// factors P and Q) as the Ed25519 seed, making the output stable for any given
// RSA key.
//
// Security note: if the RSA key is compromised, the derived Ed25519 key is also
// compromised. This is a one-way derivation; the original RSA key cannot be
// recovered from the output.
func DeriveEd25519KeyFromRSA(key *rsa.PrivateKey) (ed25519.PrivateKey, error) {
	seed, err := RSASeedBytes(key)
	if err != nil {
		return nil, fmt.Errorf("could not extract seed from RSA key: %w", err)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// validRSABits is the set of accepted RSA key sizes for DeriveRSAKeyFromEd25519.
var validRSABits = map[int]struct{}{
	2048: {},
	3072: {},
	4096: {},
}

// rsaPublicExponent is the standard RSA public exponent (2^16 + 1 = 65537).
const rsaPublicExponent = 65537

// deriveRSAKeyFromDomainHash generates an RSA private key of the given bit size
// from a pre-computed 32-byte domain hash. The hash is used as the AES-256 seed
// for a deterministic CTR-mode PRNG that drives prime generation.
//
// Callers are responsible for constructing a properly domain-separated hash
// before passing it in; this function treats the bytes as opaque key material.
// bits must be 2048, 3072, or 4096.
func deriveRSAKeyFromDomainHash(domainHash [32]byte, bits int) (*rsa.PrivateKey, error) {
	if _, ok := validRSABits[bits]; !ok {
		return nil, fmt.Errorf("invalid RSA bit size %d: must be 2048, 3072, or 4096", bits)
	}

	prng, err := newDeterministicReader(domainHash[:])
	if err != nil {
		return nil, fmt.Errorf("could not create deterministic reader: %w", err)
	}

	// Generate P and Q as distinct primes from the deterministic stream.
	// deterministicPrime uses ProbablyPrime(0) (Baillie-PSW) which is fully
	// deterministic — unlike crypto/rand.Prime which calls ProbablyPrime(20)
	// and draws random Miller-Rabin witnesses from crypto/rand.Reader.
	halfBits := bits / 2 //nolint:mnd
	p, err := deterministicPrime(prng, halfBits)
	if err != nil {
		return nil, fmt.Errorf("could not generate prime P: %w", err)
	}

	var q *big.Int
	for {
		q, err = deterministicPrime(prng, halfBits)
		if err != nil {
			return nil, fmt.Errorf("could not generate prime Q: %w", err)
		}
		if p.Cmp(q) != 0 {
			break
		}
	}

	// Compute the RSA key components.
	one := big.NewInt(1)
	n := new(big.Int).Mul(p, q)
	pm1 := new(big.Int).Sub(p, one)
	qm1 := new(big.Int).Sub(q, one)
	phi := new(big.Int).Mul(pm1, qm1)

	e := big.NewInt(rsaPublicExponent)
	d := new(big.Int).ModInverse(e, phi)
	if d == nil {
		return nil, fmt.Errorf("could not compute RSA private exponent: gcd(e, phi) != 1")
	}

	rsaKey := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			N: n,
			E: rsaPublicExponent,
		},
		D:      d,
		Primes: []*big.Int{p, q},
	}
	rsaKey.Precompute()

	if err := rsaKey.Validate(); err != nil {
		return nil, fmt.Errorf("derived RSA key failed validation: %w", err)
	}

	return rsaKey, nil
}

// DeriveRSAKeyFromEd25519 deterministically derives an RSA private key from an
// Ed25519 private key. The derivation domain-separates the Ed25519 seed with
// the label "seedify:rsa-from-ed25519:", hashes it with SHA-256 to produce a
// 32-byte AES-256 key, and feeds an AES-256-CTR stream as the source of
// randomness for prime generation. This ensures the same Ed25519 key and bit
// size always produce the same RSA key.
//
// bits must be 2048, 3072, or 4096. 4096 is strongly recommended.
// This function is computationally expensive because it involves prime search.
//
// Security note: if the Ed25519 key is compromised, the derived RSA key is also
// compromised. This is a one-way derivation; the original Ed25519 key cannot be
// recovered from the output.
func DeriveRSAKeyFromEd25519(key *ed25519.PrivateKey, bits int) (*rsa.PrivateKey, error) {
	// Domain-separate the Ed25519 seed before using it as an AES key so that
	// the raw seed bytes are never directly exposed to the AES cipher.
	label := []byte("seedify:rsa-from-ed25519:")
	input := make([]byte, len(label)+len(key.Seed()))
	copy(input, label)
	copy(input[len(label):], key.Seed())

	return deriveRSAKeyFromDomainHash(sha256.Sum256(input), bits)
}

// DKIMKeypair holds the formatted DKIM key material ready for use with a mail server.
type DKIMKeypair struct {
	// PrivateKeyPEM is the RSA private key encoded as a PKCS#8 PEM block
	// ("-----BEGIN PRIVATE KEY-----"). This is the format expected by OpenDKIM,
	// rspamd, Postfix, and Exim. DKIM private keys are stored without passphrase
	// protection — secure the file with filesystem permissions (0600).
	PrivateKeyPEM []byte

	// DNSTXTRecord is the complete value for the DKIM selector DNS TXT record,
	// ready to publish under <selector>._domainkey.<domain> in TXT format.
	// Example: v=DKIM1; k=rsa; p=<base64-encoded-public-key>
	DNSTXTRecord string

	// PublicKeyBase64 is the base64-encoded DER-encoded SubjectPublicKeyInfo
	// public key, without the surrounding v=DKIM1 wrapper. This is the raw
	// value that goes in the p= field of the DNS TXT record.
	PublicKeyBase64 string
}

// DeriveDKIMKeypair deterministically derives an RSA keypair from an Ed25519
// private key and formats the output for immediate use with a DKIM-signing mail
// server (OpenDKIM, rspamd, Postfix milter, Exim).
//
// The selector is mixed into the domain-separation label as
// "seedify:dkim:<selector>:", so different selectors produce completely different
// RSA keys from the same source Ed25519 key. This makes selector-based key
// rotation possible without needing a new Ed25519 source key.
//
// The private key is marshalled as a PKCS#8 PEM block ("BEGIN PRIVATE KEY"), which
// is the format most modern MTAs and DKIM libraries expect. No passphrase is
// applied because DKIM private keys are conventionally stored unencrypted and
// protected only by filesystem permissions (0600, root-owned).
//
// The public key is marshalled as a PKIX DER SubjectPublicKeyInfo structure,
// base64-encoded, and wrapped in a v=DKIM1; k=rsa; p=<key> DNS TXT value ready
// to paste into your DNS zone under <selector>._domainkey.<domain>.
//
// bits must be 2048, 3072, or 4096. 2048 bits is the current industry standard
// for DKIM; 4096 produces a longer DNS TXT record that some providers may need
// to split across multiple 255-byte strings.
//
// Security note: the derived DKIM key is cryptographically linked to the source
// Ed25519 key. Compromising either key compromises both.
func DeriveDKIMKeypair(key *ed25519.PrivateKey, selector string, bits int) (*DKIMKeypair, error) {
	// Bind the selector into the domain-separation label so that each selector
	// name produces a distinct RSA key from the same source Ed25519 key.
	label := []byte("seedify:dkim:" + selector + ":")
	input := make([]byte, len(label)+len(key.Seed()))
	copy(input, label)
	copy(input[len(label):], key.Seed())

	rsaKey, err := deriveRSAKeyFromDomainHash(sha256.Sum256(input), bits)
	if err != nil {
		return nil, fmt.Errorf("could not derive RSA key for DKIM: %w", err)
	}

	// Marshal the private key as PKCS#8 DER, then wrap in a PEM block.
	// OpenDKIM and most modern MTA DKIM implementations expect the "BEGIN PRIVATE KEY"
	// header (PKCS#8), not the legacy "BEGIN RSA PRIVATE KEY" header (PKCS#1).
	privDER, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		return nil, fmt.Errorf("could not marshal DKIM private key: %w", err)
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})

	// Marshal the public key as PKIX DER (SubjectPublicKeyInfo) and base64-encode
	// it for the DNS TXT record p= field.
	pubDER, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("could not marshal DKIM public key: %w", err)
	}
	pubBase64 := base64.StdEncoding.EncodeToString(pubDER)

	return &DKIMKeypair{
		PrivateKeyPEM:   privPEM,
		DNSTXTRecord:    fmt.Sprintf("v=DKIM1; k=rsa; p=%s", pubBase64),
		PublicKeyBase64: pubBase64,
	}, nil
}

// pgpEpoch is the fixed creation timestamp stamped on all OpenPGP keys
// derived by seedify. Using a well-known past date instead of a live
// clock or a hash-derived value guarantees two properties simultaneously:
//  1. Determinism: the same source Ed25519 key always produces the same
//     OpenPGP fingerprint, regardless of when the command is run.
//  2. GPG compatibility: GPG rejects keys with creation times in the future,
//     so using a hash-derived timestamp risks rejection for some source keys.
var pgpEpoch = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)

// PGPKeypair holds the two RSA keys needed to build a standard OpenPGP secret
// key block: a primary key used for signing and certification ([SC]), and an
// encryption subkey ([E]). Both are derived deterministically from the same
// Ed25519 source key using distinct domain-separation labels.
type PGPKeypair struct {
	// PrimaryKey is the RSA private key for the OpenPGP primary key packet.
	// It carries the [SC] (Sign + Certify) usage flags.
	PrimaryKey *rsa.PrivateKey

	// EncryptSubkey is the RSA private key for the OpenPGP encryption subkey
	// packet. It carries the [E] (Encrypt) usage flag.
	EncryptSubkey *rsa.PrivateKey

	// CreationTime is the fixed seedify PGP epoch (2020-01-01 00:00:00 UTC).
	// See pgpEpoch for the rationale behind using a constant rather than a
	// hash-derived or live-clock value.
	CreationTime time.Time
}

// DerivePGPKeypair deterministically derives a pair of RSA private keys from
// an Ed25519 private key, intended for use as an OpenPGP primary key (signing /
// certification) and encryption subkey.
//
// The two keys are derived with separate domain-separation labels:
//   - Primary key: "seedify:pgp:primary:" + seed
//   - Encryption subkey: "seedify:pgp:encrypt:" + seed
//
// This guarantees that the primary key and the encryption subkey are
// cryptographically independent, even though they share the same source.
//
// The CreationTime field is derived deterministically from the first 4 bytes
// of the primary domain hash, ensuring the OpenPGP fingerprint is stable
// across invocations with the same source key.
//
// bits must be 2048, 3072, or 4096. 4096 is strongly recommended.
//
// Security note: if the source Ed25519 key is compromised, both derived RSA
// keys are also compromised. This is a one-way derivation.
func DerivePGPKeypair(key *ed25519.PrivateKey, bits int) (*PGPKeypair, error) {
	// Derive the primary (signing/certifying) RSA key.
	primaryLabel := []byte("seedify:pgp:primary:")
	primaryInput := make([]byte, len(primaryLabel)+len(key.Seed()))
	copy(primaryInput, primaryLabel)
	copy(primaryInput[len(primaryLabel):], key.Seed())
	primaryHash := sha256.Sum256(primaryInput)

	primaryKey, err := deriveRSAKeyFromDomainHash(primaryHash, bits)
	if err != nil {
		return nil, fmt.Errorf("could not derive PGP primary key: %w", err)
	}

	// Derive the encryption subkey RSA key using a distinct label so it is
	// independent of the primary key even though both share the same seed.
	encryptLabel := []byte("seedify:pgp:encrypt:")
	encryptInput := make([]byte, len(encryptLabel)+len(key.Seed()))
	copy(encryptInput, encryptLabel)
	copy(encryptInput[len(encryptLabel):], key.Seed())

	encryptKey, err := deriveRSAKeyFromDomainHash(sha256.Sum256(encryptInput), bits)
	if err != nil {
		return nil, fmt.Errorf("could not derive PGP encryption subkey: %w", err)
	}

	return &PGPKeypair{
		PrimaryKey:    primaryKey,
		EncryptSubkey: encryptKey,
		CreationTime:  pgpEpoch,
	}, nil
}

// combineSeedPassphrase combines a seed passphrase with the SSH key seed to create
// combined entropy. The passphrase is hashed with SHA256 to produce 32 bytes,
// which are then XORed with the key seed to combine the entropy deterministically.
func combineSeedPassphrase(keySeed []byte, seedPassphrase string) []byte {
	// Hash the passphrase to get 32 bytes of entropy
	passphraseHash := sha256.Sum256([]byte(seedPassphrase))

	// Combine by XORing the hashed passphrase with the key seed
	combined := make([]byte, len(keySeed))
	for i := range keySeed {
		combined[i] = keySeed[i] ^ passphraseHash[i]
	}

	return combined
}

// ToMnemonicWithLength takes an ed25519 private key and returns a mnemonic
// phrase of the specified word count. This is an auxiliary utility function.
// The generated phrases cannot be used with FromMnemonic to recover the
// original key if the word count is less than 24.
//
// If seedPassphrase is provided (non-empty), it will be combined with the
// SSH key seed to add additional entropy: ENTROPY(seed-passphrase) + ENTROPY(ssh-key).
//
// The word count is prepended to the entropy to ensure different word counts
// generate completely different words, not just truncated versions of the same phrase.
// Exception: For 24 words (when brave is false), the raw seed is used directly
// without prepending word count or hashing.
//
// If brave is true, the hash of "brave" is prepended to the entropy (similar to
// word count) to generate a different set of words.
//
// birthday is a Unix timestamp used as the polyseed creation date for 16-word
// mnemonics. Use PolyseedEpoch for deterministic output, or 0 for the current
// time. This parameter is ignored for non-polyseed word counts.
//
// Valid word counts are: 12, 15, 16, 18, 21, or 24.
// The entropy size is determined by the word count:
//   - 12 words = 128 bits (16 bytes) - BIP39
//   - 15 words = 160 bits (20 bytes) - BIP39
//   - 16 words = 150 bits (19 bytes) - Polyseed format
//   - 18 words = 192 bits (24 bytes) - BIP39
//   - 21 words = 224 bits (28 bytes) - BIP39
//   - 24 words = 256 bits (32 bytes) - BIP39
func ToMnemonicWithLength(key *ed25519.PrivateKey, wordCount int, seedPassphrase string, brave bool, birthday uint64) (string, error) {
	// Delegate to ToMnemonicWithPrefix with "brave" as the prefix when brave is true
	var prefix string
	if brave {
		prefix = "brave"
	}
	return ToMnemonicWithPrefix(key, wordCount, seedPassphrase, prefix, birthday)
}

// ToMnemonicWithPrefix takes an ed25519 private key and returns a mnemonic
// phrase of the specified word count. It is a generalization of ToMnemonicWithLength
// that accepts an arbitrary prefix string instead of a boolean brave flag.
//
// If prefix is non-empty, the hash of the prefix string is prepended to the entropy
// (similar to how the word count is prepended) to generate a completely different
// set of words. This allows generating distinct seed phrases for different
// applications (e.g., "brave" for Brave Sync, "wallet" for Brave Wallet).
//
// If seedPassphrase is provided (non-empty), it will be combined with the
// SSH key seed to add additional entropy: ENTROPY(seed-passphrase) + ENTROPY(ssh-key).
//
// The word count is prepended to the entropy to ensure different word counts
// generate completely different words, not just truncated versions of the same phrase.
// Exception: For 24 words (when prefix is empty), the raw seed is used directly
// without prepending word count or hashing.
//
// birthday is a Unix timestamp used as the polyseed creation date for 16-word
// mnemonics. Use PolyseedEpoch for deterministic output, or 0 for the current
// time. This parameter is ignored for non-polyseed word counts.
//
// Valid word counts are: 12, 15, 16, 18, 21, or 24.
// The entropy size is determined by the word count:
//   - 12 words = 128 bits (16 bytes) - BIP39
//   - 15 words = 160 bits (20 bytes) - BIP39
//   - 16 words = 150 bits (19 bytes) - Polyseed format
//   - 18 words = 192 bits (24 bytes) - BIP39
//   - 21 words = 224 bits (28 bytes) - BIP39
//   - 24 words = 256 bits (32 bytes) - BIP39
func ToMnemonicWithPrefix(key *ed25519.PrivateKey, wordCount int, seedPassphrase string, prefix string, birthday uint64) (string, error) {
	return toMnemonicFromSeedBytes(key.Seed(), wordCount, seedPassphrase, prefix, birthday)
}

// toMnemonicFromSeedBytes is the internal implementation shared by all mnemonic generation
// functions regardless of key type. It accepts a raw 32-byte seed (extracted from the
// key by the caller) and applies passphrase mixing, word-count prefixing, and hashing
// before producing the final BIP-39 or Polyseed mnemonic.
func toMnemonicFromSeedBytes(fullSeed []byte, wordCount int, seedPassphrase string, prefix string, birthday uint64) (string, error) {
	// Combine with seed passphrase if provided
	var combinedSeed []byte
	if seedPassphrase != "" {
		combinedSeed = combineSeedPassphrase(fullSeed, seedPassphrase)
	} else {
		combinedSeed = make([]byte, len(fullSeed))
		copy(combinedSeed, fullSeed)
	}

	// Special handling for 24 words with no prefix: use raw seed directly
	// Skip word count prefix and hashing to ensure compatibility
	if wordCount == 24 && prefix == "" {
		// Use the combined seed directly as entropy (32 bytes for 24 words)
		words, err := bip39.NewMnemonic(combinedSeed)
		if err != nil {
			return "", fmt.Errorf("could not create a mnemonic set of words: %w", err)
		}
		return words, nil
	}

	// Prepend word count to the seed to ensure different word counts generate
	// completely different words. We encode the word count as a uint16 (wordCountBytesSize bytes)
	// to ensure it's properly incorporated into the entropy.
	// Valid word counts are 12, 15, 16, 18, 21, 24 - all within uint16 range.
	wordCountBytes := make([]byte, wordCountBytesSize)
	binary.BigEndian.PutUint16(wordCountBytes, uint16(wordCount)) //nolint:gosec

	// If a prefix is provided, prepend its hash (similar to word count)
	var prefixBytes []byte
	if prefix != "" {
		// Hash the prefix string and take the first 2 bytes (same size as word count)
		prefixHash := sha256.Sum256([]byte(prefix))
		hashPrefix := prefixHash[:2]
		// Combine hash prefix with word count prefix
		prefixBytes = make([]byte, len(hashPrefix)+len(wordCountBytes))
		copy(prefixBytes, hashPrefix)
		copy(prefixBytes[len(hashPrefix):], wordCountBytes)
	} else {
		prefixBytes = wordCountBytes
	}

	// Combine prefix with the seed
	prefixedSeed := make([]byte, len(prefixBytes)+len(combinedSeed))
	copy(prefixedSeed, prefixBytes)
	copy(prefixedSeed[len(prefixBytes):], combinedSeed)

	// Special handling for 16 words - use polyseed format
	if wordCount == polyseedWordCount {
		// Hash the prefixed seed to get exactly 19 bytes (150 bits) for polyseed
		// We use SHA256 and take the first 19 bytes
		hash := sha256.Sum256(prefixedSeed)
		polyseedBytes := hash[:19]

		seed, err := polyseed.CreateFromBytesWithBirthday(polyseedBytes, 0, birthday)
		if err != nil {
			return "", fmt.Errorf("could not create polyseed: %w", err)
		}
		defer seed.Free()

		// Get English language (index 0) for encoding.
		// Note: Other languages may be supported in future versions based on user preference.
		lang := polyseed.GetLang(0)
		if lang == nil {
			return "", fmt.Errorf("could not get polyseed language")
		}

		// Encode to mnemonic using Monero coin (default)
		mnemonic := seed.Encode(lang, polyseed.CoinMonero)

		return mnemonic, nil
	}

	// Look up entropy size for the requested word count
	entropySize, ok := entropySizeMap[wordCount]
	if !ok {
		return "", fmt.Errorf("invalid word count: %d (must be 12, 15, 16, 18, 21, or 24)", wordCount)
	}

	// Hash the prefixed seed to get exactly the required entropy size
	// This ensures different word counts produce completely different words
	hash := sha256.Sum256(prefixedSeed)
	entropy := hash[:entropySize]

	// Generate the mnemonic from the hashed entropy
	words, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return "", fmt.Errorf("could not create a mnemonic set of words: %w", err)
	}

	return words, nil
}

// BraveSync25thWord returns the 25th word for Brave Sync based on the current date.
// The 25th word changes daily and is calculated from the epoch date
// "Tue, 10 May 2022 00:00:00 GMT". The number of days since the epoch is used
// as an index into the BIP39 English word list.
//
// This function replicates the logic from the JavaScript implementation at
// https://alexeybarabash.github.io/25th-brave-sync-word/
//
// Returns an error if the current date is before the epoch date or if the
// calculated index is out of bounds for the BIP39 word list.
func BraveSync25thWord() (string, error) {
	return BraveSync25thWordForDate(time.Now().UTC())
}

// BraveSync25thWordForDate returns the 25th word for Brave Sync for a specific date.
// This allows you to get the 25th word for any date, not just today.
//
// The date parameter should be in UTC. The number of days since the epoch
// "Tue, 10 May 2022 00:00:00 GMT" is used as an index into the BIP39 English word list.
//
// Returns an error if the provided date is before the epoch date or if the
// calculated index is out of bounds for the BIP39 word list.
func BraveSync25thWordForDate(date time.Time) (string, error) {
	// Parse the epoch date: "Tue, 10 May 2022 00:00:00 GMT"
	// Using RFC1123 format which matches the JavaScript Date string format
	epochDate, err := time.Parse(time.RFC1123, "Tue, 10 May 2022 00:00:00 GMT")
	if err != nil {
		return "", fmt.Errorf("could not parse epoch date: %w", err)
	}

	// Ensure we're working in UTC
	epochDate = epochDate.UTC()
	dateUTC := date.UTC()

	// Calculate the difference in milliseconds, then convert to days
	deltaInMsec := dateUTC.Sub(epochDate).Milliseconds()
	deltaInDays := float64(deltaInMsec) / (24 * 60 * 60 * msPerSecond)
	// Round to nearest integer to match JavaScript Math.round() behavior
	deltaInDaysRounded := int64(math.Round(deltaInDays))

	// Check if date is before epoch
	if deltaInDaysRounded < 0 {
		return "", fmt.Errorf("date %s is before the epoch date %s", dateUTC.Format(time.RFC1123), epochDate.Format(time.RFC1123))
	}

	// Get the BIP39 English word list
	wordList := wordlists.English
	if wordList == nil {
		return "", fmt.Errorf("BIP39 English word list is not available")
	}

	// Check bounds - BIP39 word list has 2048 words (indices 0-2047)
	if deltaInDaysRounded >= int64(len(wordList)) {
		return "", fmt.Errorf("calculated index %d is out of bounds for BIP39 word list (max index: %d)", deltaInDaysRounded, len(wordList)-1)
	}

	// Return the word at the calculated index
	return wordList[deltaInDaysRounded], nil
}

// ToMnemonicWithBraveSync generates a 24-word mnemonic with the "brave" prefix
// and appends the 25th word from Brave Sync. This creates a 25-word phrase
// suitable for use with Brave Sync.
//
// The function generates 24 words using the same logic as ToMnemonicWithLength
// with the brave flag set, then appends the current day's 25th word from Brave Sync.
func ToMnemonicWithBraveSync(key *ed25519.PrivateKey, seedPassphrase string) (string, error) {
	// Generate 24 words with brave flag set
	mnemonic24, err := ToMnemonicWithLength(key, bip39MaxWordCount, seedPassphrase, true, 0)
	if err != nil {
		return "", fmt.Errorf("could not generate 24-word mnemonic: %w", err)
	}

	// Get the 25th word for today
	word25, err := BraveSync25thWord()
	if err != nil {
		return "", fmt.Errorf("could not get 25th word: %w", err)
	}

	// Append the 25th word to the 24-word phrase
	return fmt.Sprintf("%s %s", mnemonic24, word25), nil
}

// ToMnemonicWithLengthFromRSA is the RSA analogue of ToMnemonicWithLength.
// It extracts a 32-byte seed from the RSA private key via RSASeedBytes and
// delegates to the same internal mnemonic pipeline.
//
// See ToMnemonicWithLength for parameter and word-count documentation.
func ToMnemonicWithLengthFromRSA(key *rsa.PrivateKey, wordCount int, seedPassphrase string, brave bool, birthday uint64) (string, error) {
	var prefix string
	if brave {
		prefix = "brave"
	}
	return ToMnemonicWithPrefixFromRSA(key, wordCount, seedPassphrase, prefix, birthday)
}

// ToMnemonicWithPrefixFromRSA is the RSA analogue of ToMnemonicWithPrefix.
// It extracts a 32-byte seed from the RSA private key via RSASeedBytes and
// delegates to the same internal mnemonic pipeline.
//
// See ToMnemonicWithPrefix for parameter and word-count documentation.
func ToMnemonicWithPrefixFromRSA(key *rsa.PrivateKey, wordCount int, seedPassphrase string, prefix string, birthday uint64) (string, error) {
	seed, err := RSASeedBytes(key)
	if err != nil {
		return "", fmt.Errorf("could not extract seed from RSA key: %w", err)
	}
	return toMnemonicFromSeedBytes(seed, wordCount, seedPassphrase, prefix, birthday)
}

// ToMnemonicWithBraveSyncFromRSA is the RSA analogue of ToMnemonicWithBraveSync.
// It generates a 24-word mnemonic with the "brave" prefix from an RSA key and
// appends the current day's 25th Brave Sync word.
func ToMnemonicWithBraveSyncFromRSA(key *rsa.PrivateKey, seedPassphrase string) (string, error) {
	mnemonic24, err := ToMnemonicWithLengthFromRSA(key, bip39MaxWordCount, seedPassphrase, true, 0)
	if err != nil {
		return "", fmt.Errorf("could not generate 24-word mnemonic: %w", err)
	}

	word25, err := BraveSync25thWord()
	if err != nil {
		return "", fmt.Errorf("could not get 25th word: %w", err)
	}

	return fmt.Sprintf("%s %s", mnemonic24, word25), nil
}

// NostrKeys contains all Nostr key formats derived from a mnemonic.
type NostrKeys struct {
	// Npub is the public key in bech32 format (starts with "npub1")
	Npub string
	// Nsec is the private key in bech32 format (starts with "nsec1")
	Nsec string
	// PubKeyHex is the raw public key in hexadecimal format (64 characters)
	PubKeyHex string
	// PrivKeyHex is the raw private key in hexadecimal format (64 characters)
	PrivKeyHex string
}

// DeriveNostrKeysWithHex derives Nostr keys from a BIP39 mnemonic phrase.
// Returns keys in both bech32 (npub/nsec) and hexadecimal formats.
// The function follows NIP-06 standard: it converts the mnemonic to a BIP39 seed,
// then uses BIP32 hierarchical derivation with path m/44'/1237'/0'/0/0 to derive
// the Nostr private key.
//
// Parameters:
//   - mnemonic: A valid BIP39 mnemonic phrase (12, 15, 18, 21, or 24 words)
//   - bip39Passphrase: Optional BIP39 passphrase (empty string if not used)
//
// Returns:
//   - NostrKeys: Contains npub, nsec, pubKeyHex, and privKeyHex
//   - error: Any error that occurred during derivation
func DeriveNostrKeysWithHex(mnemonic string, bip39Passphrase string) (*NostrKeys, error) {
	// Validate mnemonic and convert to BIP39 seed with optional passphrase
	seed, err := bip39.NewSeedWithErrorChecking(mnemonic, bip39Passphrase)
	if err != nil {
		return nil, fmt.Errorf("invalid mnemonic: %w", err)
	}

	// Derive private key using NIP-06 standard BIP32 path: m/44'/1237'/0'/0/0
	privateKeyHex, err := nip06.PrivateKeyFromSeed(seed)
	if err != nil {
		return nil, fmt.Errorf("failed to derive private key from seed: %w", err)
	}

	// Derive public key from private key
	publicKeyHex, err := nostr.GetPublicKey(privateKeyHex)
	if err != nil {
		return nil, fmt.Errorf("failed to derive public key: %w", err)
	}

	// Encode keys to npub/nsec format using nip19 bech32 encoding
	npub, err := nip19.EncodePublicKey(publicKeyHex)
	if err != nil {
		return nil, fmt.Errorf("failed to encode public key: %w", err)
	}

	nsec, err := nip19.EncodePrivateKey(privateKeyHex)
	if err != nil {
		return nil, fmt.Errorf("failed to encode private key: %w", err)
	}

	return &NostrKeys{
		Npub:       npub,
		Nsec:       nsec,
		PubKeyHex:  publicKeyHex,
		PrivKeyHex: privateKeyHex,
	}, nil
}

// DeriveNostrKeys derives Nostr keys (npub/nsec) from a BIP39 mnemonic phrase.
// The function follows NIP-06 standard: it converts the mnemonic to a BIP39 seed,
// then uses BIP32 hierarchical derivation with path m/44'/1237'/0'/0/0 to derive
// the Nostr private key. The keys are encoded to npub/nsec format using bech32.
//
// Parameters:
//   - mnemonic: A valid BIP39 mnemonic phrase (12, 15, 18, 21, or 24 words)
//   - bip39Passphrase: Optional BIP39 passphrase (empty string if not used)
//
// Returns:
//   - npub: The Nostr public key in bech32 format (starts with "npub1")
//   - nsec: The Nostr private key in bech32 format (starts with "nsec1")
//   - error: Any error that occurred during derivation
func DeriveNostrKeys(mnemonic string, bip39Passphrase string) (npub string, nsec string, err error) {
	// Validate mnemonic and convert to BIP39 seed with optional passphrase
	seed, err := bip39.NewSeedWithErrorChecking(mnemonic, bip39Passphrase)
	if err != nil {
		return "", "", fmt.Errorf("invalid mnemonic: %w", err)
	}

	// Derive private key using NIP-06 standard BIP32 path: m/44'/1237'/0'/0/0
	privateKeyHex, err := nip06.PrivateKeyFromSeed(seed)
	if err != nil {
		return "", "", fmt.Errorf("failed to derive private key from seed: %w", err)
	}

	// Derive public key from private key
	publicKeyHex, err := nostr.GetPublicKey(privateKeyHex)
	if err != nil {
		return "", "", fmt.Errorf("failed to derive public key: %w", err)
	}

	// Encode keys to npub/nsec format using nip19 bech32 encoding
	npub, err = nip19.EncodePublicKey(publicKeyHex)
	if err != nil {
		return "", "", fmt.Errorf("failed to encode public key: %w", err)
	}

	nsec, err = nip19.EncodePrivateKey(privateKeyHex)
	if err != nil {
		return "", "", fmt.Errorf("failed to encode private key: %w", err)
	}

	return npub, nsec, nil
}

// DeriveNostrKeysFromEd25519 derives Nostr keys (npub/nsec) directly from an Ed25519 private key.
// This function is used to derive Nostr keys from SSH keys without going through seed phrases.
//
// Parameters:
//   - key: An Ed25519 private key (e.g., from an SSH key)
//
// Returns:
//   - npub: The Nostr public key in bech32 format (starts with "npub1")
//   - nsec: The Nostr private key in bech32 format (starts with "nsec1")
//   - error: Any error that occurred during derivation
func DeriveNostrKeysFromEd25519(key *ed25519.PrivateKey) (npub string, nsec string, err error) {
	// Get the public key from the private key
	publicKey := (*key).Public().(ed25519.PublicKey)

	// Convert keys to hex strings (Nostr uses hex-encoded keys)
	// Use Seed() to get the 32-byte private key seed, not the full 64-byte key
	privateKeyHex := hex.EncodeToString((*key).Seed())
	publicKeyHex := hex.EncodeToString(publicKey)

	// Encode keys to npub/nsec format using nip19 bech32 encoding
	npub, err = nip19.EncodePublicKey(publicKeyHex)
	if err != nil {
		return "", "", fmt.Errorf("failed to encode public key: %w", err)
	}

	nsec, err = nip19.EncodePrivateKey(privateKeyHex)
	if err != nil {
		return "", "", fmt.Errorf("failed to encode private key: %w", err)
	}

	return npub, nsec, nil
}

// DeriveNostrKeysFromRSA derives Nostr keys (npub/nsec) directly from an RSA private key.
// A 32-byte seed is extracted via RSASeedBytes (SHA256 of the two prime factors P and Q),
// then used as the secp256k1 private scalar to derive a valid Nostr key pair.
//
// Parameters:
//   - key: An RSA private key (e.g., from an SSH key)
//
// Returns:
//   - npub: The Nostr public key in bech32 format (starts with "npub1")
//   - nsec: The Nostr private key in bech32 format (starts with "nsec1")
//   - error: Any error that occurred during derivation
func DeriveNostrKeysFromRSA(key *rsa.PrivateKey) (npub string, nsec string, err error) {
	seed, seedErr := RSASeedBytes(key)
	if seedErr != nil {
		return "", "", fmt.Errorf("could not extract seed from RSA key: %w", seedErr)
	}

	privateKeyHex := hex.EncodeToString(seed)

	// Derive the secp256k1 public key from the private scalar
	publicKeyHex, pubErr := nostr.GetPublicKey(privateKeyHex)
	if pubErr != nil {
		return "", "", fmt.Errorf("failed to derive Nostr public key: %w", pubErr)
	}

	npub, err = nip19.EncodePublicKey(publicKeyHex)
	if err != nil {
		return "", "", fmt.Errorf("failed to encode public key: %w", err)
	}

	nsec, err = nip19.EncodePrivateKey(privateKeyHex)
	if err != nil {
		return "", "", fmt.Errorf("failed to encode private key: %w", err)
	}

	return npub, nsec, nil
}

// DeriveBitcoinAddress derives a Bitcoin address from a BIP39 mnemonic phrase.
// The function follows BIP44 standard with derivation path m/44'/0'/0'/0/0.
// It returns a P2PKH address (starts with "1") for Bitcoin mainnet.
//
// Parameters:
//   - mnemonic: A valid BIP39 mnemonic phrase (12, 15, 18, 21, or 24 words)
//   - bip39Passphrase: Optional BIP39 passphrase (empty string if not used)
//
// Returns:
//   - address: The Bitcoin P2PKH address
//   - error: Any error that occurred during derivation
func DeriveBitcoinAddress(mnemonic string, bip39Passphrase string) (string, error) {
	// Validate mnemonic and convert to BIP39 seed with optional passphrase
	seed, err := bip39.NewSeedWithErrorChecking(mnemonic, bip39Passphrase)
	if err != nil {
		return "", fmt.Errorf("invalid mnemonic: %w", err)
	}

	// Create master key from seed
	masterKey, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		return "", fmt.Errorf("failed to create master key: %w", err)
	}

	// Derive BIP44 path: m/44'/0'/0'/0/0
	// 44' = purpose (BIP44)
	// 0' = coin type (Bitcoin)
	// 0' = account
	// 0 = change (external)
	// 0 = address index
	purpose, err := masterKey.Derive(hdkeychain.HardenedKeyStart + 44) //nolint:mnd
	if err != nil {
		return "", fmt.Errorf("failed to derive purpose: %w", err)
	}

	coinType, err := purpose.Derive(hdkeychain.HardenedKeyStart + 0)
	if err != nil {
		return "", fmt.Errorf("failed to derive coin type: %w", err)
	}

	account, err := coinType.Derive(hdkeychain.HardenedKeyStart + 0)
	if err != nil {
		return "", fmt.Errorf("failed to derive account: %w", err)
	}

	change, err := account.Derive(0)
	if err != nil {
		return "", fmt.Errorf("failed to derive change: %w", err)
	}

	addressIndex, err := change.Derive(0)
	if err != nil {
		return "", fmt.Errorf("failed to derive address index: %w", err)
	}

	// Get the public key and create P2PKH address
	pubKey, err := addressIndex.ECPubKey()
	if err != nil {
		return "", fmt.Errorf("failed to get public key: %w", err)
	}

	// Create P2PKH address (starts with "1")
	pubKeyHash := btcutil.Hash160(pubKey.SerializeCompressed())
	addr, err := btcutil.NewAddressPubKeyHash(pubKeyHash, &chaincfg.MainNetParams)
	if err != nil {
		return "", fmt.Errorf("failed to create address: %w", err)
	}

	return addr.EncodeAddress(), nil
}

// DeriveBitcoinAddressSegwit derives a P2SH-P2WPKH (Nested SegWit) Bitcoin address.
// The function follows BIP49 standard with derivation path m/49'/0'/0'/0/0.
// It returns a P2SH-wrapped SegWit address (starts with "3") for Bitcoin mainnet.
//
// Parameters:
//   - mnemonic: A valid BIP39 mnemonic phrase (12, 15, 18, 21, or 24 words)
//   - bip39Passphrase: Optional BIP39 passphrase (empty string if not used)
//
// Returns:
//   - address: The Bitcoin P2SH-P2WPKH address (starts with "3")
//   - error: Any error that occurred during derivation
func DeriveBitcoinAddressSegwit(mnemonic string, bip39Passphrase string) (string, error) {
	// Validate mnemonic and convert to BIP39 seed with optional passphrase
	seed, err := bip39.NewSeedWithErrorChecking(mnemonic, bip39Passphrase)
	if err != nil {
		return "", fmt.Errorf("invalid mnemonic: %w", err)
	}

	// Create master key from seed
	masterKey, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		return "", fmt.Errorf("failed to create master key: %w", err)
	}

	// Derive BIP49 path: m/49'/0'/0'/0/0
	// 49' = purpose (BIP49 - P2SH-P2WPKH)
	// 0' = coin type (Bitcoin)
	// 0' = account
	// 0 = change (external)
	// 0 = address index
	purpose, err := masterKey.Derive(hdkeychain.HardenedKeyStart + 49) //nolint:mnd
	if err != nil {
		return "", fmt.Errorf("failed to derive purpose: %w", err)
	}

	coinType, err := purpose.Derive(hdkeychain.HardenedKeyStart + 0)
	if err != nil {
		return "", fmt.Errorf("failed to derive coin type: %w", err)
	}

	account, err := coinType.Derive(hdkeychain.HardenedKeyStart + 0)
	if err != nil {
		return "", fmt.Errorf("failed to derive account: %w", err)
	}

	change, err := account.Derive(0)
	if err != nil {
		return "", fmt.Errorf("failed to derive change: %w", err)
	}

	addressIndex, err := change.Derive(0)
	if err != nil {
		return "", fmt.Errorf("failed to derive address index: %w", err)
	}

	// Get the public key
	pubKey, err := addressIndex.ECPubKey()
	if err != nil {
		return "", fmt.Errorf("failed to get public key: %w", err)
	}

	// Create P2WPKH (witness) address first
	pubKeyHash := btcutil.Hash160(pubKey.SerializeCompressed())
	witnessAddr, err := btcutil.NewAddressWitnessPubKeyHash(pubKeyHash, &chaincfg.MainNetParams)
	if err != nil {
		return "", fmt.Errorf("failed to create witness address: %w", err)
	}

	// Wrap in P2SH to create P2SH-P2WPKH address (starts with "3")
	script, err := txscript.PayToAddrScript(witnessAddr)
	if err != nil {
		return "", fmt.Errorf("failed to create script: %w", err)
	}

	addr, err := btcutil.NewAddressScriptHash(script, &chaincfg.MainNetParams)
	if err != nil {
		return "", fmt.Errorf("failed to create P2SH address: %w", err)
	}

	return addr.EncodeAddress(), nil
}

// DeriveBitcoinAddressNativeSegwit derives a P2WPKH (Native SegWit) Bitcoin address.
// The function follows BIP84 standard with derivation path m/84'/0'/0'/0/0.
// It returns a Bech32 address (starts with "bc1q") for Bitcoin mainnet.
//
// Parameters:
//   - mnemonic: A valid BIP39 mnemonic phrase (12, 15, 18, 21, or 24 words)
//   - bip39Passphrase: Optional BIP39 passphrase (empty string if not used)
//
// Returns:
//   - address: The Bitcoin P2WPKH address (starts with "bc1q")
//   - error: Any error that occurred during derivation
func DeriveBitcoinAddressNativeSegwit(mnemonic string, bip39Passphrase string) (string, error) {
	// Validate mnemonic and convert to BIP39 seed with optional passphrase
	seed, err := bip39.NewSeedWithErrorChecking(mnemonic, bip39Passphrase)
	if err != nil {
		return "", fmt.Errorf("invalid mnemonic: %w", err)
	}

	// Create master key from seed
	masterKey, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		return "", fmt.Errorf("failed to create master key: %w", err)
	}

	// Derive BIP84 path: m/84'/0'/0'/0/0
	// 84' = purpose (BIP84 - P2WPKH native SegWit)
	// 0' = coin type (Bitcoin)
	// 0' = account
	// 0 = change (external)
	// 0 = address index
	purpose, err := masterKey.Derive(hdkeychain.HardenedKeyStart + 84) //nolint:mnd
	if err != nil {
		return "", fmt.Errorf("failed to derive purpose: %w", err)
	}

	coinType, err := purpose.Derive(hdkeychain.HardenedKeyStart + 0)
	if err != nil {
		return "", fmt.Errorf("failed to derive coin type: %w", err)
	}

	account, err := coinType.Derive(hdkeychain.HardenedKeyStart + 0)
	if err != nil {
		return "", fmt.Errorf("failed to derive account: %w", err)
	}

	change, err := account.Derive(0)
	if err != nil {
		return "", fmt.Errorf("failed to derive change: %w", err)
	}

	addressIndex, err := change.Derive(0)
	if err != nil {
		return "", fmt.Errorf("failed to derive address index: %w", err)
	}

	// Get the public key and create P2WPKH address
	pubKey, err := addressIndex.ECPubKey()
	if err != nil {
		return "", fmt.Errorf("failed to get public key: %w", err)
	}

	// Create P2WPKH address (starts with "bc1q")
	pubKeyHash := btcutil.Hash160(pubKey.SerializeCompressed())
	addr, err := btcutil.NewAddressWitnessPubKeyHash(pubKeyHash, &chaincfg.MainNetParams)
	if err != nil {
		return "", fmt.Errorf("failed to create address: %w", err)
	}

	return addr.EncodeAddress(), nil
}

// DeriveBitcoinAddressNativeSegwitAtIndex derives a P2WPKH address at the given address index.
// Path: m/84'/0'/0'/0/{addressIndex}. Index 1-19 is typically used for DNS output.
func DeriveBitcoinAddressNativeSegwitAtIndex(mnemonic string, bip39Passphrase string, addressIndex uint32) (string, error) {
	seed, err := bip39.NewSeedWithErrorChecking(mnemonic, bip39Passphrase)
	if err != nil {
		return "", fmt.Errorf("invalid mnemonic: %w", err)
	}
	masterKey, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		return "", fmt.Errorf("failed to create master key: %w", err)
	}
	path := []uint32{
		hdkeychain.HardenedKeyStart + 84,
		hdkeychain.HardenedKeyStart + 0,
		hdkeychain.HardenedKeyStart + 0,
		0,
		addressIndex,
	}
	addressKey, err := deriveBIP32Path(masterKey, path)
	if err != nil {
		return "", fmt.Errorf("failed to derive address key: %w", err)
	}
	pubKey, err := addressKey.ECPubKey()
	if err != nil {
		return "", fmt.Errorf("failed to get public key: %w", err)
	}
	pubKeyHash := btcutil.Hash160(pubKey.SerializeCompressed())
	addr, err := btcutil.NewAddressWitnessPubKeyHash(pubKeyHash, &chaincfg.MainNetParams)
	if err != nil {
		return "", fmt.Errorf("failed to create address: %w", err)
	}
	return addr.EncodeAddress(), nil
}

// DeriveSilentPaymentAddress derives a BIP 352 Silent Payment (sp1) address from a BIP39 mnemonic.
// The function follows BIP 352 derivation paths:
//   - scan key: m/352'/0'/0'/1'/0
//   - spend key: m/352'/0'/0'/0'/0
//
// It returns a bech32m-encoded address (starts with "sp1") for Bitcoin mainnet.
// Silent Payments are privacy-preserving static addresses: each payment appears on-chain
// as a unique Taproot address, making it impossible for observers to link payments.
//
// Parameters:
//   - mnemonic: A valid BIP39 mnemonic phrase (12, 15, 18, 21, or 24 words)
//   - bip39Passphrase: Optional BIP39 passphrase (empty string if not used)
//
// Returns:
//   - address: The Bitcoin Silent Payment address (starts with "sp1")
//   - error: Any error that occurred during derivation
func DeriveSilentPaymentAddress(mnemonic string, bip39Passphrase string) (string, error) {
	seed, err := bip39.NewSeedWithErrorChecking(mnemonic, bip39Passphrase)
	if err != nil {
		return "", fmt.Errorf("invalid mnemonic: %w", err)
	}
	masterKey, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		return "", fmt.Errorf("failed to create master key: %w", err)
	}

	// BIP 352: scan_private_key at m/352'/0'/0'/1'/0
	scanPath := []uint32{
		hdkeychain.HardenedKeyStart + 352,
		hdkeychain.HardenedKeyStart + 0,
		hdkeychain.HardenedKeyStart + 0,
		hdkeychain.HardenedKeyStart + 1,
		0,
	}
	scanKey, err := deriveBIP32Path(masterKey, scanPath)
	if err != nil {
		return "", fmt.Errorf("failed to derive scan key: %w", err)
	}
	scanPubKey, err := scanKey.ECPubKey()
	if err != nil {
		return "", fmt.Errorf("failed to get scan public key: %w", err)
	}
	scanPubBytes := scanPubKey.SerializeCompressed()
	if len(scanPubBytes) != 33 { //nolint:mnd // secp256k1 compressed public key size
		return "", fmt.Errorf("scan public key must be 33 bytes, got %d", len(scanPubBytes))
	}

	// BIP 352: spend_private_key at m/352'/0'/0'/0'/0
	spendPath := []uint32{
		hdkeychain.HardenedKeyStart + 352,
		hdkeychain.HardenedKeyStart + 0,
		hdkeychain.HardenedKeyStart + 0,
		hdkeychain.HardenedKeyStart + 0,
		0,
	}
	spendKey, err := deriveBIP32Path(masterKey, spendPath)
	if err != nil {
		return "", fmt.Errorf("failed to derive spend key: %w", err)
	}
	spendPubKey, err := spendKey.ECPubKey()
	if err != nil {
		return "", fmt.Errorf("failed to get spend public key: %w", err)
	}
	spendPubBytes := spendPubKey.SerializeCompressed()
	if len(spendPubBytes) != 33 { //nolint:mnd // secp256k1 compressed public key size
		return "", fmt.Errorf("spend public key must be 33 bytes, got %d", len(spendPubBytes))
	}

	// BIP 352 address encoding: bech32m with "sp" prefix, version 0
	// Data = scan_pub_key (33 bytes) || spend_pub_key (33 bytes)
	data := make([]byte, 0, 66) //nolint:mnd
	data = append(data, scanPubBytes...)
	data = append(data, spendPubBytes...)

	converted, err := bech32.ConvertBits(data, 8, 5, true) //nolint:mnd
	if err != nil {
		return "", fmt.Errorf("failed to convert bits for sp1 address: %w", err)
	}

	// Prepend version byte 0 (Silent Payment v0)
	finalData := make([]byte, 0, 1+len(converted))
	finalData = append(finalData, 0)
	finalData = append(finalData, converted...)

	encoded, err := bech32.EncodeM("sp", finalData)
	if err != nil {
		return "", fmt.Errorf("failed to encode sp1 address: %w", err)
	}
	return encoded, nil
}

// DeriveEthereumAddress derives an Ethereum address from a BIP39 mnemonic phrase.
// The function follows BIP44 standard with derivation path m/44'/60'/0'/0/0.
// It returns a checksummed Ethereum address (starts with "0x").
//
// Parameters:
//   - mnemonic: A valid BIP39 mnemonic phrase (12, 15, 18, 21, or 24 words)
//   - bip39Passphrase: Optional BIP39 passphrase (empty string if not used)
//
// Returns:
//   - address: The Ethereum address with 0x prefix
//   - error: Any error that occurred during derivation
func DeriveEthereumAddress(mnemonic string, bip39Passphrase string) (string, error) {
	// Create HD wallet from mnemonic with optional passphrase
	var wallet *hdwallet.Wallet
	var err error

	if bip39Passphrase != "" {
		// Use seed directly when passphrase is provided
		seed, seedErr := bip39.NewSeedWithErrorChecking(mnemonic, bip39Passphrase)
		if seedErr != nil {
			return "", fmt.Errorf("invalid mnemonic: %w", seedErr)
		}
		wallet, err = hdwallet.NewFromSeed(seed)
	} else {
		wallet, err = hdwallet.NewFromMnemonic(mnemonic)
	}
	if err != nil {
		return "", fmt.Errorf("failed to create wallet from mnemonic: %w", err)
	}

	// Derive BIP44 path: m/44'/60'/0'/0/0
	// 44' = purpose (BIP44)
	// 60' = coin type (Ethereum)
	// 0' = account
	// 0 = change (external)
	// 0 = address index
	path := hdwallet.MustParseDerivationPath("m/44'/60'/0'/0/0")
	account, err := wallet.Derive(path, false)
	if err != nil {
		return "", fmt.Errorf("failed to derive account: %w", err)
	}

	return account.Address.Hex(), nil
}

// DeriveTronAddress derives a Tron address from a BIP39 mnemonic phrase.
// The function follows BIP44 standard with derivation path m/44'/195'/0'/0/0.
// Tron uses the same secp256k1 key derivation and Keccak256 address computation
// as Ethereum, but encodes the address using Base58Check with a 0x41 prefix
// instead of hex with a 0x prefix. The resulting address starts with "T".
//
// Parameters:
//   - mnemonic: A valid BIP39 mnemonic phrase (12, 15, 18, 21, or 24 words)
//   - bip39Passphrase: Optional BIP39 passphrase (empty string if not used)
//
// Returns:
//   - address: The Tron address (Base58Check-encoded, starts with "T")
//   - error: Any error that occurred during derivation
func DeriveTronAddress(mnemonic string, bip39Passphrase string) (string, error) {
	// Create HD wallet from mnemonic with optional passphrase
	var wallet *hdwallet.Wallet
	var err error

	if bip39Passphrase != "" {
		// Use seed directly when passphrase is provided
		seed, seedErr := bip39.NewSeedWithErrorChecking(mnemonic, bip39Passphrase)
		if seedErr != nil {
			return "", fmt.Errorf("invalid mnemonic: %w", seedErr)
		}
		wallet, err = hdwallet.NewFromSeed(seed)
	} else {
		wallet, err = hdwallet.NewFromMnemonic(mnemonic)
	}
	if err != nil {
		return "", fmt.Errorf("failed to create wallet from mnemonic: %w", err)
	}

	// Derive BIP44 path: m/44'/195'/0'/0/0
	// 44' = purpose (BIP44)
	// 195' = coin type (Tron)
	// 0' = account
	// 0 = change (external)
	// 0 = address index
	path := hdwallet.MustParseDerivationPath("m/44'/195'/0'/0/0")
	account, err := wallet.Derive(path, false)
	if err != nil {
		return "", fmt.Errorf("failed to derive account: %w", err)
	}

	// The hdwallet library computes the Ethereum-style 20-byte address
	// (last 20 bytes of Keccak256 hash of the uncompressed public key).
	// Tron uses the same address bytes, just with a different encoding.
	addrBytes := account.Address.Bytes()

	// Encode as Tron address: Base58Check(0x41 || address_bytes)
	// 0x41 is the Tron mainnet address prefix
	return encodeTronAddress(addrBytes), nil
}

// encodeTronAddress encodes a 20-byte address as a Tron Base58Check address.
// The encoding format is: Base58(0x41 || address || checksum)
// where checksum = SHA256(SHA256(0x41 || address))[:4].
func encodeTronAddress(addrBytes []byte) string {
	// Prepend Tron mainnet prefix (0x41)
	payload := make([]byte, 0, 25)  //nolint:mnd // 1 prefix + 20 address + 4 checksum
	payload = append(payload, 0x41) //nolint:mnd // Tron mainnet address prefix
	payload = append(payload, addrBytes...)

	// Calculate checksum: first 4 bytes of double SHA256
	firstHash := sha256.Sum256(payload)
	secondHash := sha256.Sum256(firstHash[:])
	checksum := secondHash[:4]

	// Append checksum and Base58 encode
	payload = append(payload, checksum...)

	return base58.Encode(payload)
}

// DeriveSolanaAddress derives a Solana address from a BIP39 mnemonic phrase.
// The function follows SLIP-0010/BIP44 standard with derivation path m/44'/501'/0'/0'.
// Solana uses Ed25519 keys, so all path components are hardened.
// It returns a Base58-encoded public key as the Solana address.
//
// Parameters:
//   - mnemonic: A valid BIP39 mnemonic phrase (12, 15, 18, 21, or 24 words)
//   - bip39Passphrase: Optional BIP39 passphrase (empty string if not used)
//
// Returns:
//   - address: The Solana address (Base58-encoded public key)
//   - error: Any error that occurred during derivation
func DeriveSolanaAddress(mnemonic string, bip39Passphrase string) (string, error) {
	// Validate mnemonic and convert to BIP39 seed with optional passphrase
	seed, err := bip39.NewSeedWithErrorChecking(mnemonic, bip39Passphrase)
	if err != nil {
		return "", fmt.Errorf("invalid mnemonic: %w", err)
	}

	// Derive using SLIP-0010 for Ed25519
	// Path: m/44'/501'/0'/0' (all hardened for Ed25519)
	key := deriveEd25519Key(seed, []uint32{44, 501, 0, 0})

	// Generate Ed25519 public key from the derived private key
	privateKey := ed25519.NewKeyFromSeed(key)
	publicKey := privateKey.Public().(ed25519.PublicKey)

	// Solana address is the Base58-encoded public key
	return base58.Encode(publicKey), nil
}

// deriveEd25519Key derives an Ed25519 private key from a seed using SLIP-0010.
// This implements hierarchical deterministic key derivation for Ed25519 curves.
// All derivation indices are treated as hardened (as required by Ed25519).
//
// Parameters:
//   - seed: The BIP39 seed (64 bytes)
//   - path: The derivation path indices (e.g., [44, 501, 0, 0] for m/44'/501'/0'/0')
//
// Returns:
//   - key: The derived 32-byte Ed25519 private key seed
func deriveEd25519Key(seed []byte, path []uint32) []byte {
	// SLIP-0010: Use "ed25519 seed" as the HMAC key for master key generation
	hmacKey := []byte("ed25519 seed")

	// Generate master key and chain code
	h := hmac.New(sha512.New, hmacKey)
	h.Write(seed)
	sum := h.Sum(nil)

	// First 32 bytes are the private key, last 32 bytes are the chain code
	key := sum[:32]
	chainCode := sum[32:]

	// Derive each level of the path (all hardened for Ed25519)
	for _, index := range path {
		// Add hardened offset (0x80000000)
		hardenedIndex := index + 0x80000000 //nolint:mnd

		// Prepare data for HMAC: 0x00 || key || index
		data := make([]byte, 37) //nolint:mnd
		data[0] = 0x00
		copy(data[1:33], key)
		binary.BigEndian.PutUint32(data[33:], hardenedIndex)

		// Compute HMAC-SHA512
		h = hmac.New(sha512.New, chainCode)
		h.Write(data)
		sum = h.Sum(nil)

		// Update key and chain code
		key = sum[:32]
		chainCode = sum[32:]
	}

	return key
}

// DeriveMoneroAddress derives a Monero address from a polyseed mnemonic phrase.
// The function decodes the polyseed to extract the seed bytes, then derives
// the Monero spend and view keys from it.
//
// Parameters:
//   - mnemonic: A valid 16-word polyseed mnemonic phrase
//
// Returns:
//   - address: The Monero primary address (starts with "4")
//   - error: Any error that occurred during derivation
func DeriveMoneroAddress(mnemonic string) (string, error) {
	// Decode the polyseed mnemonic (auto-detects language)
	seed, _, err := polyseed.Decode(mnemonic, polyseed.CoinMonero)
	if err != nil {
		return "", fmt.Errorf("failed to decode polyseed mnemonic: %w", err)
	}
	defer seed.Free()

	// Derive the spend private key (32 bytes) from polyseed.
	// The polyseed Keygen() function returns seed bytes that need to be
	// reduced to a valid Ed25519 scalar using sc_reduce32.
	const polyseedKeySize = 32
	spendKeyBytes := seed.Keygen(polyseed.CoinMonero, polyseedKeySize)

	// Reduce the key bytes to a valid Ed25519 scalar.
	// This performs sc_reduce32 without any hashing - the key bytes are used directly.
	reducedKey := scReduce32(spendKeyBytes)

	// Create Monero private key from the reduced bytes.
	spendPrivKey, err := utils.NewPrivateKey(hex.EncodeToString(reducedKey))
	if err != nil {
		return "", fmt.Errorf("failed to create spend private key: %w", err)
	}

	// Create Monero key pair from the spend private key
	// This automatically derives the view key from the spend key
	keyPair, err := utils.NewFullKeyPairSpendPrivateKey(spendPrivKey)
	if err != nil {
		return "", fmt.Errorf("failed to create Monero key pair: %w", err)
	}

	// Get the public keys
	spendPubKey := keyPair.SpendKeyPair().PublicKey().Bytes()
	viewPubKey := keyPair.ViewKeyPair().PublicKey().Bytes()

	// Construct the address bytes: prefix (1) + spend pubkey (32) + view pubkey (32) + checksum (4)
	// Mainnet primary address prefix is 0x12
	addrData := make([]byte, 65) //nolint:mnd // 1 + 32 + 32
	addrData[0] = 0x12           // Mainnet primary address prefix
	copy(addrData[1:33], spendPubKey)
	copy(addrData[33:65], viewPubKey)

	// Calculate checksum (first 4 bytes of Keccak256 hash)
	checksum, err := utils.Keccak256Hash(addrData)
	if err != nil {
		return "", fmt.Errorf("failed to calculate checksum: %w", err)
	}

	// Append checksum to address data
	fullAddr := append(addrData, checksum[:4]...)

	// Encode using Monero's base58 encoding
	encoded, err := utils.EncodeMoneroAddress(fullAddr)
	if err != nil {
		return "", fmt.Errorf("failed to encode address: %w", err)
	}

	return string(encoded), nil
}

// DeriveMoneroSubaddressAtIndex derives a Monero receiving subaddress at the given index.
// Index 0 maps to subaddress (0,1), index 1 to (0,2), etc. Valid range: 0-19 for DNS output.
func DeriveMoneroSubaddressAtIndex(mnemonic string, index uint32) (string, error) {
	seed, _, err := polyseed.Decode(mnemonic, polyseed.CoinMonero)
	if err != nil {
		return "", fmt.Errorf("failed to decode polyseed mnemonic: %w", err)
	}
	defer seed.Free()
	const polyseedKeySize = 32
	spendKeyBytes := seed.Keygen(polyseed.CoinMonero, polyseedKeySize)
	reducedKey := scReduce32(spendKeyBytes)
	spendPrivKey, err := utils.NewPrivateKey(hex.EncodeToString(reducedKey))
	if err != nil {
		return "", fmt.Errorf("failed to create spend private key: %w", err)
	}
	keyPair, err := utils.NewFullKeyPairSpendPrivateKey(spendPrivKey)
	if err != nil {
		return "", fmt.Errorf("failed to create Monero key pair: %w", err)
	}
	viewSecKey := keyPair.ViewKeyPair().PrivateKey().Bytes()
	spendPubKey := keyPair.SpendKeyPair().PublicKey().Bytes()
	return deriveMoneroSubaddress(viewSecKey, spendPubKey, 0, index+1)
}

// MoneroKeys contains the primary address and subaddresses derived from a polyseed.
type MoneroKeys struct {
	// PrimaryAddress is the main Monero address (starts with "4")
	PrimaryAddress string
	// Subaddresses is a list of subaddresses (start with "8")
	// Index 0 is subaddress (0,1), index 1 is (0,2), etc.
	Subaddresses []string
}

// DeriveMoneroKeys derives a Monero primary address and subaddresses from a polyseed mnemonic.
// The function decodes the polyseed to extract the seed bytes, then derives
// the Monero spend and view keys, and generates the requested number of subaddresses.
//
// Parameters:
//   - mnemonic: A valid 16-word polyseed mnemonic phrase
//   - numSubaddresses: Number of subaddresses to generate (0 for none)
//
// Returns:
//   - MoneroKeys: Contains the primary address and subaddresses
//   - error: Any error that occurred during derivation
func DeriveMoneroKeys(mnemonic string, numSubaddresses int) (*MoneroKeys, error) {
	// Decode the polyseed mnemonic (auto-detects language)
	seed, _, err := polyseed.Decode(mnemonic, polyseed.CoinMonero)
	if err != nil {
		return nil, fmt.Errorf("failed to decode polyseed mnemonic: %w", err)
	}
	defer seed.Free()

	// Derive the spend private key (32 bytes) from polyseed
	const polyseedKeySize = 32
	spendKeyBytes := seed.Keygen(polyseed.CoinMonero, polyseedKeySize)

	// Reduce the key bytes to a valid Ed25519 scalar
	reducedKey := scReduce32(spendKeyBytes)

	// Create Monero private key from the reduced bytes
	spendPrivKey, err := utils.NewPrivateKey(hex.EncodeToString(reducedKey))
	if err != nil {
		return nil, fmt.Errorf("failed to create spend private key: %w", err)
	}

	// Create Monero key pair from the spend private key
	keyPair, err := utils.NewFullKeyPairSpendPrivateKey(spendPrivKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create Monero key pair: %w", err)
	}

	// Get the keys
	viewSecKey := keyPair.ViewKeyPair().PrivateKey().Bytes()
	spendPubKey := keyPair.SpendKeyPair().PublicKey().Bytes()
	viewPubKey := keyPair.ViewKeyPair().PublicKey().Bytes()

	// Build primary address
	primaryAddr, err := buildMoneroAddress(0x12, spendPubKey, viewPubKey) //nolint:mnd
	if err != nil {
		return nil, fmt.Errorf("failed to build primary address: %w", err)
	}

	// Generate subaddresses
	subaddresses := make([]string, 0, numSubaddresses)
	for i := uint32(1); i <= uint32(numSubaddresses); i++ { //nolint:gosec // numSubaddresses is always small (single digits)
		subaddr, err := deriveMoneroSubaddress(viewSecKey, spendPubKey, 0, i)
		if err != nil {
			return nil, fmt.Errorf("failed to derive subaddress (0,%d): %w", i, err)
		}
		subaddresses = append(subaddresses, subaddr)
	}

	return &MoneroKeys{
		PrimaryAddress: primaryAddr,
		Subaddresses:   subaddresses,
	}, nil
}

// buildMoneroAddress constructs a Monero address from public keys and a prefix.
func buildMoneroAddress(prefix byte, spendPubKey, viewPubKey []byte) (string, error) {
	addrData := make([]byte, 65) //nolint:mnd // 1 + 32 + 32
	addrData[0] = prefix
	copy(addrData[1:33], spendPubKey)
	copy(addrData[33:65], viewPubKey)

	checksum, err := utils.Keccak256Hash(addrData)
	if err != nil {
		return "", fmt.Errorf("failed to calculate checksum: %w", err)
	}

	fullAddr := append(addrData, checksum[:4]...)
	encoded, err := utils.EncodeMoneroAddress(fullAddr)
	if err != nil {
		return "", fmt.Errorf("failed to encode address: %w", err)
	}

	return string(encoded), nil
}

// deriveMoneroSubaddress derives a Monero subaddress at the given index.
// Subaddresses use a different derivation: D_ij = B + m*G, C_ij = a*D_ij
// where m = Hs("SubAddr" || a || i || j), B is spend public, a is view secret.
func deriveMoneroSubaddress(viewSecretKey, spendPubKey []byte, major, minor uint32) (string, error) {
	if major == 0 && minor == 0 {
		return "", fmt.Errorf("(0,0) is the primary address, not a subaddress")
	}

	// Compute m = Hs("SubAddr" || view_secret || major || minor)
	prefix := []byte("SubAddr\x00") // "SubAddr" with null terminator
	majorBytes := make([]byte, 4)   //nolint:mnd
	minorBytes := make([]byte, 4)   //nolint:mnd
	binary.LittleEndian.PutUint32(majorBytes, major)
	binary.LittleEndian.PutUint32(minorBytes, minor)

	data := make([]byte, 0, len(prefix)+32+8) //nolint:mnd
	data = append(data, prefix...)
	data = append(data, viewSecretKey...)
	data = append(data, majorBytes...)
	data = append(data, minorBytes...)

	// Hash to scalar: Hs(data) = sc_reduce32(keccak256(data))
	hash, err := utils.Keccak256Hash(data)
	if err != nil {
		return "", fmt.Errorf("failed to hash subaddress data: %w", err)
	}
	m := scReduce32(hash)

	// Convert m to edwards25519 scalar
	mScalar, err := edwards25519.NewScalar().SetCanonicalBytes(m)
	if err != nil {
		return "", fmt.Errorf("failed to create scalar from m: %w", err)
	}

	// Compute m*G (base point multiplication)
	mG := edwards25519.NewIdentityPoint().ScalarBaseMult(mScalar)

	// Parse spend public key as a point
	spendPubPoint, err := edwards25519.NewIdentityPoint().SetBytes(spendPubKey)
	if err != nil {
		return "", fmt.Errorf("failed to parse spend public key: %w", err)
	}

	// D_ij = B + m*G (subaddress spend public key)
	subSpendPub := edwards25519.NewIdentityPoint().Add(spendPubPoint, mG)

	// Parse view secret key as scalar
	viewSecScalar, err := edwards25519.NewScalar().SetCanonicalBytes(viewSecretKey)
	if err != nil {
		return "", fmt.Errorf("failed to create scalar from view secret: %w", err)
	}

	// C_ij = a * D_ij (subaddress view public key)
	subViewPub := edwards25519.NewIdentityPoint().ScalarMult(viewSecScalar, subSpendPub)

	// Build subaddress with prefix 0x2A (42 decimal)
	return buildMoneroAddress(0x2A, subSpendPub.Bytes(), subViewPub.Bytes()) //nolint:mnd
}

// scReduce32 reduces a 32-byte value to a valid Ed25519 scalar.
// This ensures the value is in canonical form (< L) for use as a Monero private key.
// L = 2^252 + 27742317777372353535851937790883648493 (the Ed25519 curve order).
//
// This function performs proper modular reduction mod L using the edwards25519 library.
// The input bytes are padded to 64 bytes and then reduced using SetUniformBytes,
// which performs the correct sc_reduce operation.
func scReduce32(input []byte) []byte {
	if len(input) != 32 { //nolint:mnd
		return input
	}

	// First try to interpret as a canonical scalar directly
	scalar, err := edwards25519.NewScalar().SetCanonicalBytes(input)
	if err == nil {
		return scalar.Bytes()
	}

	// If not canonical, perform proper modular reduction.
	// Pad to 64 bytes and use SetUniformBytes which performs sc_reduce.
	padded := make([]byte, 64) //nolint:mnd
	copy(padded, input)

	scalar, err = edwards25519.NewScalar().SetUniformBytes(padded)
	if err != nil {
		// Fallback: clear high bits (should rarely happen)
		result := make([]byte, 32) //nolint:mnd
		copy(result, input)
		result[31] &= 0x0F
		return result
	}

	return scalar.Bytes()
}

// Extended key version bytes for SLIP-0132 encoding.
// These are used to encode extended keys with version prefixes that indicate
// the derivation path standard (BIP44, BIP49, BIP84).
const (
	// BIP49 SegWit (ypub/yprv).
	ypubVersion uint32 = 0x049D7CB2
	yprvVersion uint32 = 0x049D7878
	// BIP84 Native SegWit (zpub/zprv).
	zpubVersion uint32 = 0x04B24746
	zprvVersion uint32 = 0x04B2430C
	// BIP48 Multisig P2SH-P2WSH (Ypub/Yprv). Uppercase denotes multisig.
	multisigYpubVersion uint32 = 0x0295B43F
	multisigYprvVersion uint32 = 0x0295B005
	// BIP48 Multisig P2WSH (Zpub/Zprv). Uppercase denotes multisig.
	multisigZpubVersion uint32 = 0x02AA7ED3
	multisigZprvVersion uint32 = 0x02AA7A99
)

// BitcoinKeys contains the address and private key (WIF) for a Bitcoin derivation.
type BitcoinKeys struct {
	Address    string
	PrivateWIF string
}

// BitcoinExtendedKeys contains the extended public and private keys at the account level.
type BitcoinExtendedKeys struct {
	ExtendedPublicKey  string
	ExtendedPrivateKey string
}

// PayNymKeys contains the BIP47 payment code (PayNym) and notification address.
// The payment code is derived from m/47'/0'/0'; the notification address from m/47'/0'/0'/0.
type PayNymKeys struct {
	// PaymentCode is the Base58Check-encoded BIP47 payment code (starts with "PM8T").
	PaymentCode string
	// NotificationAddress is the P2PKH address for receiving notification transactions.
	NotificationAddress string
}

// BitcoinMultisigExtendedKeys contains both the specific format (Ypub/Yprv or Zpub/Zprv)
// and the standard format (xpub/xprv) for multisig extended keys.
// The standard keys are nested conceptually below the specific keys.
type BitcoinMultisigExtendedKeys struct {
	// ExtendedPublicKey is the specific format (e.g., Ypub or Zpub)
	ExtendedPublicKey string
	// ExtendedPrivateKey is the specific format (e.g., Yprv or Zprv)
	ExtendedPrivateKey string
	// StandardPublicKey is the standard xpub format
	StandardPublicKey string
	// StandardPrivateKey is the standard xprv format
	StandardPrivateKey string
}

// deriveBIP32Path derives a key at the given BIP32 path from a master key.
// The path is specified as a slice of uint32 values, where values >= 0x80000000
// are hardened derivations.
func deriveBIP32Path(masterKey *hdkeychain.ExtendedKey, path []uint32) (*hdkeychain.ExtendedKey, error) {
	key := masterKey
	var err error
	for _, index := range path {
		key, err = key.Derive(index)
		if err != nil {
			return nil, fmt.Errorf("failed to derive at index %d: %w", index, err)
		}
	}
	return key, nil
}

// payNymBase58Version is the version byte for BIP47 payment code Base58Check encoding.
// 0x47 produces "P" as the first character of the serialized form.
const payNymBase58Version = 0x47

// DerivePayNym derives a BIP47 payment code (PayNym) and notification address from a BIP39 mnemonic.
// The function follows BIP47 with derivation path m/47'/0'/0' for the payment code and
// m/47'/0'/0'/0 for the notification address. Uses version 1 payment code format.
//
// Parameters:
//   - mnemonic: A valid BIP39 mnemonic phrase (12, 15, 18, 21, or 24 words)
//   - bip39Passphrase: Optional BIP39 passphrase (empty string if not used)
//
// Returns:
//   - PayNymKeys: The payment code and notification address
//   - error: Any error that occurred during derivation
func DerivePayNym(mnemonic string, bip39Passphrase string) (*PayNymKeys, error) {
	seed, err := bip39.NewSeedWithErrorChecking(mnemonic, bip39Passphrase)
	if err != nil {
		return nil, fmt.Errorf("invalid mnemonic: %w", err)
	}

	masterKey, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		return nil, fmt.Errorf("failed to create master key: %w", err)
	}

	// Derive BIP47 identity key: m/47'/0'/0'
	identityPath := []uint32{
		hdkeychain.HardenedKeyStart + 47, // purpose (BIP47)
		hdkeychain.HardenedKeyStart + 0,  // coin type (Bitcoin)
		hdkeychain.HardenedKeyStart + 0,  // identity (account)
	}
	identityKey, err := deriveBIP32Path(masterKey, identityPath)
	if err != nil {
		return nil, fmt.Errorf("failed to derive BIP47 identity key: %w", err)
	}

	// Derive notification key: m/47'/0'/0'/0 (0th non-hardened child)
	notificationKey, err := identityKey.Derive(0)
	if err != nil {
		return nil, fmt.Errorf("failed to derive notification key: %w", err)
	}

	// Build payment code: neuter identity key for public derivation
	identityPubKey, err := identityKey.Neuter()
	if err != nil {
		return nil, fmt.Errorf("failed to neuter identity key: %w", err)
	}

	pubKey, err := identityPubKey.ECPubKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get public key: %w", err)
	}
	chainCode := identityPubKey.ChainCode()
	if len(chainCode) != bip32ChainCodeSize {
		return nil, fmt.Errorf("invalid chain code length: %d", len(chainCode))
	}

	// BIP47 Version 1 payment code binary format (80 bytes):
	// Byte 0: version (0x01)
	// Byte 1: features (0x00)
	// Byte 2: sign (0x02 or 0x03 for compressed pubkey)
	// Bytes 3-34: x value (32 bytes)
	// Bytes 35-66: chain code (32 bytes)
	// Bytes 67-79: reserved for future expansion, zero-filled
	pubKeyBytes := pubKey.SerializeCompressed()
	if len(pubKeyBytes) != compressedPubKeySize {
		return nil, fmt.Errorf("invalid public key length: %d", len(pubKeyBytes))
	}
	signByte := pubKeyBytes[0]
	if signByte != 0x02 && signByte != 0x03 {
		return nil, fmt.Errorf("invalid compressed pubkey prefix: 0x%02x", signByte)
	}
	xValue := pubKeyBytes[1:33]

	payload := make([]byte, 80) //nolint:mnd
	payload[0] = 0x01           // version 1
	payload[1] = 0x00           // features
	payload[2] = signByte
	copy(payload[3:35], xValue)
	copy(payload[35:67], chainCode)
	// bytes 67-79 remain zero

	paymentCode := encodeBase58Check(payNymBase58Version, payload)

	// Create notification address (P2PKH) from the notification key
	notifPubKey, err := notificationKey.ECPubKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get notification public key: %w", err)
	}
	pubKeyHash := btcutil.Hash160(notifPubKey.SerializeCompressed())
	addr, err := btcutil.NewAddressPubKeyHash(pubKeyHash, &chaincfg.MainNetParams)
	if err != nil {
		return nil, fmt.Errorf("failed to create notification address: %w", err)
	}

	return &PayNymKeys{
		PaymentCode:         paymentCode,
		NotificationAddress: addr.EncodeAddress(),
	}, nil
}

// DeriveBitcoinLegacyKeys derives a Bitcoin Legacy P2PKH address and its WIF private key.
// The function follows BIP44 standard with derivation path m/44'/0'/0'/0/0.
//
// Parameters:
//   - mnemonic: A valid BIP39 mnemonic phrase (12, 15, 18, 21, or 24 words)
//   - bip39Passphrase: Optional BIP39 passphrase (empty string if not used)
//
// Returns:
//   - BitcoinKeys: The address and WIF-encoded private key
//   - error: Any error that occurred during derivation
func DeriveBitcoinLegacyKeys(mnemonic string, bip39Passphrase string) (*BitcoinKeys, error) {
	// Validate mnemonic and convert to BIP39 seed with optional passphrase
	seed, err := bip39.NewSeedWithErrorChecking(mnemonic, bip39Passphrase)
	if err != nil {
		return nil, fmt.Errorf("invalid mnemonic: %w", err)
	}

	// Create master key from seed
	masterKey, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		return nil, fmt.Errorf("failed to create master key: %w", err)
	}

	// Derive BIP44 path: m/44'/0'/0'/0/0
	path := []uint32{
		hdkeychain.HardenedKeyStart + 44, // purpose
		hdkeychain.HardenedKeyStart + 0,  // coin type (Bitcoin)
		hdkeychain.HardenedKeyStart + 0,  // account
		0,                                // change (external)
		0,                                // address index
	}
	addressKey, err := deriveBIP32Path(masterKey, path)
	if err != nil {
		return nil, fmt.Errorf("failed to derive address key: %w", err)
	}

	// Get the public key and create P2PKH address
	pubKey, err := addressKey.ECPubKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get public key: %w", err)
	}
	pubKeyHash := btcutil.Hash160(pubKey.SerializeCompressed())
	addr, err := btcutil.NewAddressPubKeyHash(pubKeyHash, &chaincfg.MainNetParams)
	if err != nil {
		return nil, fmt.Errorf("failed to create address: %w", err)
	}

	// Get the private key in WIF format
	privKey, err := addressKey.ECPrivKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get private key: %w", err)
	}
	wif, err := btcutil.NewWIF(privKey, &chaincfg.MainNetParams, true)
	if err != nil {
		return nil, fmt.Errorf("failed to create WIF: %w", err)
	}

	return &BitcoinKeys{
		Address:    addr.EncodeAddress(),
		PrivateWIF: wif.String(),
	}, nil
}

// DeriveBitcoinSegwitKeys derives a Bitcoin SegWit P2SH-P2WPKH address and its WIF private key.
// The function follows BIP49 standard with derivation path m/49'/0'/0'/0/0.
//
// Parameters:
//   - mnemonic: A valid BIP39 mnemonic phrase (12, 15, 18, 21, or 24 words)
//   - bip39Passphrase: Optional BIP39 passphrase (empty string if not used)
//
// Returns:
//   - BitcoinKeys: The address and WIF-encoded private key
//   - error: Any error that occurred during derivation
func DeriveBitcoinSegwitKeys(mnemonic string, bip39Passphrase string) (*BitcoinKeys, error) {
	// Validate mnemonic and convert to BIP39 seed with optional passphrase
	seed, err := bip39.NewSeedWithErrorChecking(mnemonic, bip39Passphrase)
	if err != nil {
		return nil, fmt.Errorf("invalid mnemonic: %w", err)
	}

	// Create master key from seed
	masterKey, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		return nil, fmt.Errorf("failed to create master key: %w", err)
	}

	// Derive BIP49 path: m/49'/0'/0'/0/0
	path := []uint32{
		hdkeychain.HardenedKeyStart + 49, // purpose (BIP49)
		hdkeychain.HardenedKeyStart + 0,  // coin type (Bitcoin)
		hdkeychain.HardenedKeyStart + 0,  // account
		0,                                // change (external)
		0,                                // address index
	}
	addressKey, err := deriveBIP32Path(masterKey, path)
	if err != nil {
		return nil, fmt.Errorf("failed to derive address key: %w", err)
	}

	// Get the public key
	pubKey, err := addressKey.ECPubKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get public key: %w", err)
	}

	// Create P2WPKH (witness) address first
	pubKeyHash := btcutil.Hash160(pubKey.SerializeCompressed())
	witnessAddr, err := btcutil.NewAddressWitnessPubKeyHash(pubKeyHash, &chaincfg.MainNetParams)
	if err != nil {
		return nil, fmt.Errorf("failed to create witness address: %w", err)
	}

	// Wrap in P2SH to create P2SH-P2WPKH address (starts with "3")
	script, err := txscript.PayToAddrScript(witnessAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to create script: %w", err)
	}
	addr, err := btcutil.NewAddressScriptHash(script, &chaincfg.MainNetParams)
	if err != nil {
		return nil, fmt.Errorf("failed to create P2SH address: %w", err)
	}

	// Get the private key in WIF format
	privKey, err := addressKey.ECPrivKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get private key: %w", err)
	}
	wif, err := btcutil.NewWIF(privKey, &chaincfg.MainNetParams, true)
	if err != nil {
		return nil, fmt.Errorf("failed to create WIF: %w", err)
	}

	return &BitcoinKeys{
		Address:    addr.EncodeAddress(),
		PrivateWIF: wif.String(),
	}, nil
}

// DeriveBitcoinNativeSegwitKeys derives a Bitcoin Native SegWit P2WPKH address and its WIF private key.
// The function follows BIP84 standard with derivation path m/84'/0'/0'/0/0.
//
// Parameters:
//   - mnemonic: A valid BIP39 mnemonic phrase (12, 15, 18, 21, or 24 words)
//   - bip39Passphrase: Optional BIP39 passphrase (empty string if not used)
//
// Returns:
//   - BitcoinKeys: The address and WIF-encoded private key
//   - error: Any error that occurred during derivation
func DeriveBitcoinNativeSegwitKeys(mnemonic string, bip39Passphrase string) (*BitcoinKeys, error) {
	// Validate mnemonic and convert to BIP39 seed with optional passphrase
	seed, err := bip39.NewSeedWithErrorChecking(mnemonic, bip39Passphrase)
	if err != nil {
		return nil, fmt.Errorf("invalid mnemonic: %w", err)
	}

	// Create master key from seed
	masterKey, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		return nil, fmt.Errorf("failed to create master key: %w", err)
	}

	// Derive BIP84 path: m/84'/0'/0'/0/0
	path := []uint32{
		hdkeychain.HardenedKeyStart + 84, // purpose (BIP84)
		hdkeychain.HardenedKeyStart + 0,  // coin type (Bitcoin)
		hdkeychain.HardenedKeyStart + 0,  // account
		0,                                // change (external)
		0,                                // address index
	}
	addressKey, err := deriveBIP32Path(masterKey, path)
	if err != nil {
		return nil, fmt.Errorf("failed to derive address key: %w", err)
	}

	// Get the public key and create P2WPKH address
	pubKey, err := addressKey.ECPubKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get public key: %w", err)
	}
	pubKeyHash := btcutil.Hash160(pubKey.SerializeCompressed())
	addr, err := btcutil.NewAddressWitnessPubKeyHash(pubKeyHash, &chaincfg.MainNetParams)
	if err != nil {
		return nil, fmt.Errorf("failed to create address: %w", err)
	}

	// Get the private key in WIF format
	privKey, err := addressKey.ECPrivKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get private key: %w", err)
	}
	wif, err := btcutil.NewWIF(privKey, &chaincfg.MainNetParams, true)
	if err != nil {
		return nil, fmt.Errorf("failed to create WIF: %w", err)
	}

	return &BitcoinKeys{
		Address:    addr.EncodeAddress(),
		PrivateWIF: wif.String(),
	}, nil
}

// encodeExtendedKey encodes an extended key with a custom version prefix.
// This is used to create ypub/yprv, zpub/zprv, and multisig variants.
func encodeExtendedKey(key *hdkeychain.ExtendedKey, version uint32) string {
	// Get the serialized key (78 bytes)
	serialized := key.String()

	// Decode the base58check (extended keys use 4-byte version, not 1-byte)
	decoded, err := base58.Decode(serialized)
	if err != nil {
		return ""
	}

	// Verify we have enough data (78 bytes + 4 bytes checksum = 82 bytes)
	if len(decoded) < 82 { //nolint:mnd
		return ""
	}

	// Get payload without checksum
	payload := decoded[:78]

	// Replace the first 4 bytes (version) with our custom version
	versionBytes := make([]byte, 4) //nolint:mnd
	binary.BigEndian.PutUint32(versionBytes, version)
	copy(payload[0:4], versionBytes)

	// Calculate new checksum (double SHA256, first 4 bytes)
	firstHash := sha256.Sum256(payload)
	secondHash := sha256.Sum256(firstHash[:])
	checksum := secondHash[:4]

	// Append checksum and encode
	result := append(payload, checksum...)

	return base58.Encode(result)
}

// DeriveBitcoinMasterFingerprint derives the master key fingerprint from a BIP39 mnemonic.
// The fingerprint is the first 4 bytes of HASH160(compressed_master_public_key),
// encoded as a lowercase hex string (8 characters). This is commonly used in
// wallet descriptors and PSBTs (e.g., [d219d86d/48'/0'/0'/2']xpub...).
//
// Parameters:
//   - mnemonic: A valid BIP39 mnemonic phrase
//   - bip39Passphrase: Optional BIP39 passphrase (empty string if not used)
//
// Returns:
//   - fingerprint: The 4-byte master fingerprint as a lowercase hex string
//   - error: Any error that occurred during derivation
func DeriveBitcoinMasterFingerprint(mnemonic string, bip39Passphrase string) (string, error) {
	// Validate mnemonic and convert to BIP39 seed with optional passphrase
	seed, err := bip39.NewSeedWithErrorChecking(mnemonic, bip39Passphrase)
	if err != nil {
		return "", fmt.Errorf("invalid mnemonic: %w", err)
	}

	// Create master key from seed
	masterKey, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		return "", fmt.Errorf("failed to create master key: %w", err)
	}

	// Get the master public key
	masterPubKey, err := masterKey.ECPubKey()
	if err != nil {
		return "", fmt.Errorf("failed to get master public key: %w", err)
	}

	// Compute HASH160 of the compressed public key and take the first 4 bytes
	pubKeyHash := btcutil.Hash160(masterPubKey.SerializeCompressed())
	fingerprint := pubKeyHash[:4]

	return hex.EncodeToString(fingerprint), nil
}

// DeriveBitcoinMasterExtendedKeys derives the master extended public and private keys.
// Returns xpub and xprv at the master level (m).
// This is the root of the HD wallet tree, before any BIP44/49/84 derivation.
//
// Parameters:
//   - mnemonic: A valid BIP39 mnemonic phrase
//   - bip39Passphrase: Optional BIP39 passphrase (empty string if not used)
//
// Returns:
//   - BitcoinExtendedKeys: The xpub and xprv at master level
//   - error: Any error that occurred during derivation
func DeriveBitcoinMasterExtendedKeys(mnemonic string, bip39Passphrase string) (*BitcoinExtendedKeys, error) {
	// Validate mnemonic and convert to BIP39 seed with optional passphrase
	seed, err := bip39.NewSeedWithErrorChecking(mnemonic, bip39Passphrase)
	if err != nil {
		return nil, fmt.Errorf("invalid mnemonic: %w", err)
	}

	// Create master key from seed
	masterKey, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		return nil, fmt.Errorf("failed to create master key: %w", err)
	}

	// Get the public key version (neuter removes the private key)
	masterPubKey, err := masterKey.Neuter()
	if err != nil {
		return nil, fmt.Errorf("failed to neuter key: %w", err)
	}

	return &BitcoinExtendedKeys{
		ExtendedPublicKey:  masterPubKey.String(),
		ExtendedPrivateKey: masterKey.String(),
	}, nil
}

// DeriveBitcoinLegacyExtendedKeys derives the extended public and private keys for BIP44 Legacy.
// Returns xpub and xprv at the account level (m/44'/0'/0').
//
// Parameters:
//   - mnemonic: A valid BIP39 mnemonic phrase
//   - bip39Passphrase: Optional BIP39 passphrase (empty string if not used)
//
// Returns:
//   - BitcoinExtendedKeys: The xpub and xprv at account level
//   - error: Any error that occurred during derivation
func DeriveBitcoinLegacyExtendedKeys(mnemonic string, bip39Passphrase string) (*BitcoinExtendedKeys, error) {
	// Validate mnemonic and convert to BIP39 seed with optional passphrase
	seed, err := bip39.NewSeedWithErrorChecking(mnemonic, bip39Passphrase)
	if err != nil {
		return nil, fmt.Errorf("invalid mnemonic: %w", err)
	}

	// Create master key from seed
	masterKey, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		return nil, fmt.Errorf("failed to create master key: %w", err)
	}

	// Derive to account level: m/44'/0'/0'
	path := []uint32{
		hdkeychain.HardenedKeyStart + 44, // purpose
		hdkeychain.HardenedKeyStart + 0,  // coin type (Bitcoin)
		hdkeychain.HardenedKeyStart + 0,  // account
	}
	accountKey, err := deriveBIP32Path(masterKey, path)
	if err != nil {
		return nil, fmt.Errorf("failed to derive account key: %w", err)
	}

	// Get the public key version (neuter removes the private key)
	accountPubKey, err := accountKey.Neuter()
	if err != nil {
		return nil, fmt.Errorf("failed to neuter key: %w", err)
	}

	return &BitcoinExtendedKeys{
		ExtendedPublicKey:  accountPubKey.String(), // Already xpub format
		ExtendedPrivateKey: accountKey.String(),    // Already xprv format
	}, nil
}

// DeriveBitcoinSegwitExtendedKeys derives the extended public and private keys for BIP49 SegWit.
// Returns ypub and yprv at the account level (m/49'/0'/0').
//
// Parameters:
//   - mnemonic: A valid BIP39 mnemonic phrase
//   - bip39Passphrase: Optional BIP39 passphrase (empty string if not used)
//
// Returns:
//   - BitcoinExtendedKeys: The ypub and yprv at account level
//   - error: Any error that occurred during derivation
func DeriveBitcoinSegwitExtendedKeys(mnemonic string, bip39Passphrase string) (*BitcoinExtendedKeys, error) {
	// Validate mnemonic and convert to BIP39 seed with optional passphrase
	seed, err := bip39.NewSeedWithErrorChecking(mnemonic, bip39Passphrase)
	if err != nil {
		return nil, fmt.Errorf("invalid mnemonic: %w", err)
	}

	// Create master key from seed
	masterKey, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		return nil, fmt.Errorf("failed to create master key: %w", err)
	}

	// Derive to account level: m/49'/0'/0'
	path := []uint32{
		hdkeychain.HardenedKeyStart + 49, // purpose (BIP49)
		hdkeychain.HardenedKeyStart + 0,  // coin type (Bitcoin)
		hdkeychain.HardenedKeyStart + 0,  // account
	}
	accountKey, err := deriveBIP32Path(masterKey, path)
	if err != nil {
		return nil, fmt.Errorf("failed to derive account key: %w", err)
	}

	// Get the public key version (neuter removes the private key)
	accountPubKey, err := accountKey.Neuter()
	if err != nil {
		return nil, fmt.Errorf("failed to neuter key: %w", err)
	}

	// Encode with ypub/yprv version bytes
	return &BitcoinExtendedKeys{
		ExtendedPublicKey:  encodeExtendedKey(accountPubKey, ypubVersion),
		ExtendedPrivateKey: encodeExtendedKey(accountKey, yprvVersion),
	}, nil
}

// DeriveBitcoinNativeSegwitExtendedKeys derives the extended public and private keys for BIP84 Native SegWit.
// Returns zpub and zprv at the account level (m/84'/0'/0').
//
// Parameters:
//   - mnemonic: A valid BIP39 mnemonic phrase
//   - bip39Passphrase: Optional BIP39 passphrase (empty string if not used)
//
// Returns:
//   - BitcoinExtendedKeys: The zpub and zprv at account level
//   - error: Any error that occurred during derivation
func DeriveBitcoinNativeSegwitExtendedKeys(mnemonic string, bip39Passphrase string) (*BitcoinExtendedKeys, error) {
	// Validate mnemonic and convert to BIP39 seed with optional passphrase
	seed, err := bip39.NewSeedWithErrorChecking(mnemonic, bip39Passphrase)
	if err != nil {
		return nil, fmt.Errorf("invalid mnemonic: %w", err)
	}

	// Create master key from seed
	masterKey, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		return nil, fmt.Errorf("failed to create master key: %w", err)
	}

	// Derive to account level: m/84'/0'/0'
	path := []uint32{
		hdkeychain.HardenedKeyStart + 84, // purpose (BIP84)
		hdkeychain.HardenedKeyStart + 0,  // coin type (Bitcoin)
		hdkeychain.HardenedKeyStart + 0,  // account
	}
	accountKey, err := deriveBIP32Path(masterKey, path)
	if err != nil {
		return nil, fmt.Errorf("failed to derive account key: %w", err)
	}

	// Get the public key version (neuter removes the private key)
	accountPubKey, err := accountKey.Neuter()
	if err != nil {
		return nil, fmt.Errorf("failed to neuter key: %w", err)
	}

	// Encode with zpub/zprv version bytes
	return &BitcoinExtendedKeys{
		ExtendedPublicKey:  encodeExtendedKey(accountPubKey, zpubVersion),
		ExtendedPrivateKey: encodeExtendedKey(accountKey, zprvVersion),
	}, nil
}

// DeriveBitcoinMultisigLegacyKeys derives a 1-of-1 multisig P2SH address and its WIF private key.
// The function follows BIP48 standard with derivation path m/48'/0'/0'/0'/0/0.
// Script type 0' indicates P2SH (legacy multisig).
//
// Parameters:
//   - mnemonic: A valid BIP39 mnemonic phrase
//   - bip39Passphrase: Optional BIP39 passphrase (empty string if not used)
//
// Returns:
//   - BitcoinKeys: The P2SH multisig address and WIF-encoded private key
//   - error: Any error that occurred during derivation
func DeriveBitcoinMultisigLegacyKeys(mnemonic string, bip39Passphrase string) (*BitcoinKeys, error) {
	// Validate mnemonic and convert to BIP39 seed with optional passphrase
	seed, err := bip39.NewSeedWithErrorChecking(mnemonic, bip39Passphrase)
	if err != nil {
		return nil, fmt.Errorf("invalid mnemonic: %w", err)
	}

	// Create master key from seed
	masterKey, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		return nil, fmt.Errorf("failed to create master key: %w", err)
	}

	// Derive BIP48 path: m/48'/0'/0'/0'/0/0
	// 48' = purpose (BIP48 multisig)
	// 0' = coin type (Bitcoin)
	// 0' = account
	// 0' = script type (P2SH legacy)
	// 0 = change (external)
	// 0 = address index
	path := []uint32{
		hdkeychain.HardenedKeyStart + 48, // purpose (BIP48)
		hdkeychain.HardenedKeyStart + 0,  // coin type (Bitcoin)
		hdkeychain.HardenedKeyStart + 0,  // account
		hdkeychain.HardenedKeyStart + 0,  // script type (P2SH)
		0,                                // change (external)
		0,                                // address index
	}
	addressKey, err := deriveBIP32Path(masterKey, path)
	if err != nil {
		return nil, fmt.Errorf("failed to derive address key: %w", err)
	}

	// Get the public key
	pubKey, err := addressKey.ECPubKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get public key: %w", err)
	}

	// Create 1-of-1 multisig script: OP_1 <pubkey> OP_1 OP_CHECKMULTISIG
	builder := txscript.NewScriptBuilder()
	builder.AddOp(txscript.OP_1)
	builder.AddData(pubKey.SerializeCompressed())
	builder.AddOp(txscript.OP_1)
	builder.AddOp(txscript.OP_CHECKMULTISIG)
	multisigScript, err := builder.Script()
	if err != nil {
		return nil, fmt.Errorf("failed to build multisig script: %w", err)
	}

	// Create P2SH address from the multisig script
	scriptHash := btcutil.Hash160(multisigScript)
	addr, err := btcutil.NewAddressScriptHashFromHash(scriptHash, &chaincfg.MainNetParams)
	if err != nil {
		return nil, fmt.Errorf("failed to create P2SH address: %w", err)
	}

	// Get the private key in WIF format
	privKey, err := addressKey.ECPrivKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get private key: %w", err)
	}
	wif, err := btcutil.NewWIF(privKey, &chaincfg.MainNetParams, true)
	if err != nil {
		return nil, fmt.Errorf("failed to create WIF: %w", err)
	}

	return &BitcoinKeys{
		Address:    addr.EncodeAddress(),
		PrivateWIF: wif.String(),
	}, nil
}

// DeriveBitcoinMultisigSegwitKeys derives a 1-of-1 multisig P2SH-P2WSH address and its WIF private key.
// The function follows BIP48 standard with derivation path m/48'/0'/0'/1'/0/0.
// Script type 1' indicates P2SH-P2WSH (nested SegWit multisig).
//
// Parameters:
//   - mnemonic: A valid BIP39 mnemonic phrase
//   - bip39Passphrase: Optional BIP39 passphrase (empty string if not used)
//
// Returns:
//   - BitcoinKeys: The P2SH-P2WSH multisig address and WIF-encoded private key
//   - error: Any error that occurred during derivation
func DeriveBitcoinMultisigSegwitKeys(mnemonic string, bip39Passphrase string) (*BitcoinKeys, error) {
	// Validate mnemonic and convert to BIP39 seed with optional passphrase
	seed, err := bip39.NewSeedWithErrorChecking(mnemonic, bip39Passphrase)
	if err != nil {
		return nil, fmt.Errorf("invalid mnemonic: %w", err)
	}

	// Create master key from seed
	masterKey, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		return nil, fmt.Errorf("failed to create master key: %w", err)
	}

	// Derive BIP48 path: m/48'/0'/0'/1'/0/0
	// 48' = purpose (BIP48 multisig)
	// 0' = coin type (Bitcoin)
	// 0' = account
	// 1' = script type (P2SH-P2WSH nested SegWit)
	// 0 = change (external)
	// 0 = address index
	path := []uint32{
		hdkeychain.HardenedKeyStart + 48, // purpose (BIP48)
		hdkeychain.HardenedKeyStart + 0,  // coin type (Bitcoin)
		hdkeychain.HardenedKeyStart + 0,  // account
		hdkeychain.HardenedKeyStart + 1,  // script type (P2SH-P2WSH)
		0,                                // change (external)
		0,                                // address index
	}
	addressKey, err := deriveBIP32Path(masterKey, path)
	if err != nil {
		return nil, fmt.Errorf("failed to derive address key: %w", err)
	}

	// Get the public key
	pubKey, err := addressKey.ECPubKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get public key: %w", err)
	}

	// Create 1-of-1 multisig witness script: OP_1 <pubkey> OP_1 OP_CHECKMULTISIG
	builder := txscript.NewScriptBuilder()
	builder.AddOp(txscript.OP_1)
	builder.AddData(pubKey.SerializeCompressed())
	builder.AddOp(txscript.OP_1)
	builder.AddOp(txscript.OP_CHECKMULTISIG)
	witnessScript, err := builder.Script()
	if err != nil {
		return nil, fmt.Errorf("failed to build witness script: %w", err)
	}

	// Create P2WSH address from the witness script
	witnessScriptHash := sha256.Sum256(witnessScript)
	p2wshAddr, err := btcutil.NewAddressWitnessScriptHash(witnessScriptHash[:], &chaincfg.MainNetParams)
	if err != nil {
		return nil, fmt.Errorf("failed to create P2WSH address: %w", err)
	}

	// Wrap in P2SH to create P2SH-P2WSH address
	p2wshScript, err := txscript.PayToAddrScript(p2wshAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to create P2WSH script: %w", err)
	}
	addr, err := btcutil.NewAddressScriptHash(p2wshScript, &chaincfg.MainNetParams)
	if err != nil {
		return nil, fmt.Errorf("failed to create P2SH address: %w", err)
	}

	// Get the private key in WIF format
	privKey, err := addressKey.ECPrivKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get private key: %w", err)
	}
	wif, err := btcutil.NewWIF(privKey, &chaincfg.MainNetParams, true)
	if err != nil {
		return nil, fmt.Errorf("failed to create WIF: %w", err)
	}

	return &BitcoinKeys{
		Address:    addr.EncodeAddress(),
		PrivateWIF: wif.String(),
	}, nil
}

// DeriveBitcoinMultisigNativeSegwitKeys derives a 1-of-1 multisig P2WSH address and its WIF private key.
// The function follows BIP48 standard with derivation path m/48'/0'/0'/2'/0/0.
// Script type 2' indicates P2WSH (native SegWit multisig).
//
// Parameters:
//   - mnemonic: A valid BIP39 mnemonic phrase
//   - bip39Passphrase: Optional BIP39 passphrase (empty string if not used)
//
// Returns:
//   - BitcoinKeys: The P2WSH multisig address and WIF-encoded private key
//   - error: Any error that occurred during derivation
func DeriveBitcoinMultisigNativeSegwitKeys(mnemonic string, bip39Passphrase string) (*BitcoinKeys, error) {
	// Validate mnemonic and convert to BIP39 seed with optional passphrase
	seed, err := bip39.NewSeedWithErrorChecking(mnemonic, bip39Passphrase)
	if err != nil {
		return nil, fmt.Errorf("invalid mnemonic: %w", err)
	}

	// Create master key from seed
	masterKey, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		return nil, fmt.Errorf("failed to create master key: %w", err)
	}

	// Derive BIP48 path: m/48'/0'/0'/2'/0/0
	// 48' = purpose (BIP48 multisig)
	// 0' = coin type (Bitcoin)
	// 0' = account
	// 2' = script type (P2WSH native SegWit)
	// 0 = change (external)
	// 0 = address index
	path := []uint32{
		hdkeychain.HardenedKeyStart + 48, // purpose (BIP48)
		hdkeychain.HardenedKeyStart + 0,  // coin type (Bitcoin)
		hdkeychain.HardenedKeyStart + 0,  // account
		hdkeychain.HardenedKeyStart + 2,  // script type (P2WSH)
		0,                                // change (external)
		0,                                // address index
	}
	addressKey, err := deriveBIP32Path(masterKey, path)
	if err != nil {
		return nil, fmt.Errorf("failed to derive address key: %w", err)
	}

	// Get the public key
	pubKey, err := addressKey.ECPubKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get public key: %w", err)
	}

	// Create 1-of-1 multisig witness script: OP_1 <pubkey> OP_1 OP_CHECKMULTISIG
	builder := txscript.NewScriptBuilder()
	builder.AddOp(txscript.OP_1)
	builder.AddData(pubKey.SerializeCompressed())
	builder.AddOp(txscript.OP_1)
	builder.AddOp(txscript.OP_CHECKMULTISIG)
	witnessScript, err := builder.Script()
	if err != nil {
		return nil, fmt.Errorf("failed to build witness script: %w", err)
	}

	// Create P2WSH address from the witness script (starts with "bc1q" for 20-byte hash or "bc1q" for 32-byte)
	witnessScriptHash := sha256.Sum256(witnessScript)
	addr, err := btcutil.NewAddressWitnessScriptHash(witnessScriptHash[:], &chaincfg.MainNetParams)
	if err != nil {
		return nil, fmt.Errorf("failed to create P2WSH address: %w", err)
	}

	// Get the private key in WIF format
	privKey, err := addressKey.ECPrivKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get private key: %w", err)
	}
	wif, err := btcutil.NewWIF(privKey, &chaincfg.MainNetParams, true)
	if err != nil {
		return nil, fmt.Errorf("failed to create WIF: %w", err)
	}

	return &BitcoinKeys{
		Address:    addr.EncodeAddress(),
		PrivateWIF: wif.String(),
	}, nil
}

// DeriveBitcoinMultisigLegacyExtendedKeys derives extended keys for BIP48 Legacy multisig.
// Returns xpub and xprv at the account/script level (m/48'/0'/0'/0').
//
// Parameters:
//   - mnemonic: A valid BIP39 mnemonic phrase
//   - bip39Passphrase: Optional BIP39 passphrase (empty string if not used)
//
// Returns:
//   - BitcoinExtendedKeys: The xpub and xprv at account level
//   - error: Any error that occurred during derivation
func DeriveBitcoinMultisigLegacyExtendedKeys(mnemonic string, bip39Passphrase string) (*BitcoinExtendedKeys, error) {
	// Validate mnemonic and convert to BIP39 seed with optional passphrase
	seed, err := bip39.NewSeedWithErrorChecking(mnemonic, bip39Passphrase)
	if err != nil {
		return nil, fmt.Errorf("invalid mnemonic: %w", err)
	}

	// Create master key from seed
	masterKey, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		return nil, fmt.Errorf("failed to create master key: %w", err)
	}

	// Derive to account/script level: m/48'/0'/0'/0'
	path := []uint32{
		hdkeychain.HardenedKeyStart + 48, // purpose (BIP48)
		hdkeychain.HardenedKeyStart + 0,  // coin type (Bitcoin)
		hdkeychain.HardenedKeyStart + 0,  // account
		hdkeychain.HardenedKeyStart + 0,  // script type (P2SH)
	}
	accountKey, err := deriveBIP32Path(masterKey, path)
	if err != nil {
		return nil, fmt.Errorf("failed to derive account key: %w", err)
	}

	// Get the public key version (neuter removes the private key)
	accountPubKey, err := accountKey.Neuter()
	if err != nil {
		return nil, fmt.Errorf("failed to neuter key: %w", err)
	}

	// For legacy multisig, we use standard xpub/xprv
	return &BitcoinExtendedKeys{
		ExtendedPublicKey:  accountPubKey.String(),
		ExtendedPrivateKey: accountKey.String(),
	}, nil
}

// DeriveBitcoinMultisigSegwitExtendedKeys derives extended keys for BIP48 SegWit multisig.
// Returns Ypub/Yprv (SLIP-132 format) and xpub/xprv (standard format) at the account/script level (m/48'/0'/0'/1').
// Uppercase Y indicates multisig P2SH-P2WSH.
//
// The standard xpub/xprv keys are provided as nested alternatives to the specific Ypub/Yprv format:
//
//	Yprv ...
//	|_ xprv ...
//
// Parameters:
//   - mnemonic: A valid BIP39 mnemonic phrase
//   - bip39Passphrase: Optional BIP39 passphrase (empty string if not used)
//
// Returns:
//   - BitcoinMultisigExtendedKeys: The Ypub/Yprv and xpub/xprv at account level
//   - error: Any error that occurred during derivation
func DeriveBitcoinMultisigSegwitExtendedKeys(mnemonic string, bip39Passphrase string) (*BitcoinMultisigExtendedKeys, error) {
	// Validate mnemonic and convert to BIP39 seed with optional passphrase
	seed, err := bip39.NewSeedWithErrorChecking(mnemonic, bip39Passphrase)
	if err != nil {
		return nil, fmt.Errorf("invalid mnemonic: %w", err)
	}

	// Create master key from seed
	masterKey, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		return nil, fmt.Errorf("failed to create master key: %w", err)
	}

	// Derive to account/script level: m/48'/0'/0'/1'
	path := []uint32{
		hdkeychain.HardenedKeyStart + 48, // purpose (BIP48)
		hdkeychain.HardenedKeyStart + 0,  // coin type (Bitcoin)
		hdkeychain.HardenedKeyStart + 0,  // account
		hdkeychain.HardenedKeyStart + 1,  // script type (P2SH-P2WSH)
	}
	accountKey, err := deriveBIP32Path(masterKey, path)
	if err != nil {
		return nil, fmt.Errorf("failed to derive account key: %w", err)
	}

	// Get the public key version (neuter removes the private key)
	accountPubKey, err := accountKey.Neuter()
	if err != nil {
		return nil, fmt.Errorf("failed to neuter key: %w", err)
	}

	// Return both Ypub/Yprv (SLIP-132) and standard xpub/xprv formats
	return &BitcoinMultisigExtendedKeys{
		ExtendedPublicKey:  encodeExtendedKey(accountPubKey, multisigYpubVersion),
		ExtendedPrivateKey: encodeExtendedKey(accountKey, multisigYprvVersion),
		StandardPublicKey:  accountPubKey.String(),
		StandardPrivateKey: accountKey.String(),
	}, nil
}

// DeriveBitcoinMultisigNativeSegwitExtendedKeys derives extended keys for BIP48 Native SegWit multisig.
// Returns Zpub/Zprv (SLIP-132 format) and xpub/xprv (standard format) at the account/script level (m/48'/0'/0'/2').
// Uppercase Z indicates multisig P2WSH.
//
// The standard xpub/xprv keys are provided as nested alternatives to the specific Zpub/Zprv format:
//
//	Zprv ...
//	|_ xprv ...
//
// Parameters:
//   - mnemonic: A valid BIP39 mnemonic phrase
//   - bip39Passphrase: Optional BIP39 passphrase (empty string if not used)
//
// Returns:
//   - BitcoinMultisigExtendedKeys: The Zpub/Zprv and xpub/xprv at account level
//   - error: Any error that occurred during derivation
func DeriveBitcoinMultisigNativeSegwitExtendedKeys(mnemonic string, bip39Passphrase string) (*BitcoinMultisigExtendedKeys, error) {
	// Validate mnemonic and convert to BIP39 seed with optional passphrase
	seed, err := bip39.NewSeedWithErrorChecking(mnemonic, bip39Passphrase)
	if err != nil {
		return nil, fmt.Errorf("invalid mnemonic: %w", err)
	}

	// Create master key from seed
	masterKey, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		return nil, fmt.Errorf("failed to create master key: %w", err)
	}

	// Derive to account/script level: m/48'/0'/0'/2'
	path := []uint32{
		hdkeychain.HardenedKeyStart + 48, // purpose (BIP48)
		hdkeychain.HardenedKeyStart + 0,  // coin type (Bitcoin)
		hdkeychain.HardenedKeyStart + 0,  // account
		hdkeychain.HardenedKeyStart + 2,  // script type (P2WSH)
	}
	accountKey, err := deriveBIP32Path(masterKey, path)
	if err != nil {
		return nil, fmt.Errorf("failed to derive account key: %w", err)
	}

	// Get the public key version (neuter removes the private key)
	accountPubKey, err := accountKey.Neuter()
	if err != nil {
		return nil, fmt.Errorf("failed to neuter key: %w", err)
	}

	// Return both Zpub/Zprv (SLIP-132) and standard xpub/xprv formats
	return &BitcoinMultisigExtendedKeys{
		ExtendedPublicKey:  encodeExtendedKey(accountPubKey, multisigZpubVersion),
		ExtendedPrivateKey: encodeExtendedKey(accountKey, multisigZprvVersion),
		StandardPublicKey:  accountPubKey.String(),
		StandardPrivateKey: accountKey.String(),
	}, nil
}

// deriveBIPAddress is a helper that derives a secp256k1 address at
// m/purpose'/coinType'/0'/0/0 and returns the HASH160 of the compressed public key.
// This is the common pattern for BIP44/BIP84-based chains.
func deriveBIPAddress(mnemonic string, bip39Passphrase string, purpose uint32, coinType uint32) (pubKeyHash []byte, err error) {
	// Validate mnemonic and convert to BIP39 seed with optional passphrase
	seed, err := bip39.NewSeedWithErrorChecking(mnemonic, bip39Passphrase)
	if err != nil {
		return nil, fmt.Errorf("invalid mnemonic: %w", err)
	}

	// Create master key from seed
	masterKey, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		return nil, fmt.Errorf("failed to create master key: %w", err)
	}

	// Derive path: m/purpose'/coinType'/0'/0/0
	path := []uint32{
		hdkeychain.HardenedKeyStart + purpose,  // purpose (e.g. 44 for BIP44, 84 for BIP84)
		hdkeychain.HardenedKeyStart + coinType, // coin type
		hdkeychain.HardenedKeyStart + 0,        // account
		0,                                      // change (external)
		0,                                      // address index
	}
	addressKey, err := deriveBIP32Path(masterKey, path)
	if err != nil {
		return nil, fmt.Errorf("failed to derive address key: %w", err)
	}

	// Get the compressed public key
	pubKey, err := addressKey.ECPubKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get public key: %w", err)
	}

	compressed := pubKey.SerializeCompressed()
	hash := btcutil.Hash160(compressed)

	return hash, nil
}

// deriveBIP44Address is a convenience wrapper around deriveBIPAddress
// for BIP44 (purpose 44) derivation paths: m/44'/coinType'/0'/0/0.
func deriveBIP44Address(mnemonic string, bip39Passphrase string, coinType uint32) (pubKeyHash []byte, err error) {
	return deriveBIPAddress(mnemonic, bip39Passphrase, 44, coinType) //nolint:mnd
}

// encodeBase58Check encodes data with a version byte using Base58Check encoding.
// This is the standard encoding for Bitcoin-like addresses:
// Base58(version || payload || checksum) where checksum = SHA256(SHA256(version || payload))[:4].
func encodeBase58Check(version byte, payload []byte) string {
	// Prepend version byte
	data := make([]byte, 0, 1+len(payload)+4) //nolint:mnd
	data = append(data, version)
	data = append(data, payload...)

	// Calculate checksum: first 4 bytes of double SHA256
	firstHash := sha256.Sum256(data)
	secondHash := sha256.Sum256(firstHash[:])
	checksum := secondHash[:4]

	// Append checksum
	data = append(data, checksum...)

	return base58.Encode(data)
}

// encodeBase58CheckVersionBytes encodes data with a multi-byte version prefix using Base58Check.
// Zcash transparent (t1) addresses use a 2-byte version. Same checksum scheme as encodeBase58Check.
func encodeBase58CheckVersionBytes(version []byte, payload []byte) string {
	data := make([]byte, 0, len(version)+len(payload)+4) //nolint:mnd
	data = append(data, version...)
	data = append(data, payload...)

	firstHash := sha256.Sum256(data)
	secondHash := sha256.Sum256(firstHash[:])
	checksum := secondHash[:4]
	data = append(data, checksum...)

	return base58.Encode(data)
}

// encodeBech32Address encodes a witness program as a bech32 address with the given
// human-readable part (HRP) and witness version.
func encodeBech32Address(hrp string, witnessVersion byte, witnessProgram []byte) (string, error) {
	// Convert the witness program to 5-bit groups for bech32 encoding
	converted, err := bech32.ConvertBits(witnessProgram, 8, 5, true) //nolint:mnd
	if err != nil {
		return "", fmt.Errorf("failed to convert bits: %w", err)
	}

	// Prepend witness version
	data := make([]byte, 0, 1+len(converted))
	data = append(data, witnessVersion)
	data = append(data, converted...)

	// Encode as bech32
	encoded, err := bech32.Encode(hrp, data)
	if err != nil {
		return "", fmt.Errorf("failed to encode bech32: %w", err)
	}

	return encoded, nil
}

// DeriveLitecoinAddress derives a Litecoin native SegWit (P2WPKH) address from a BIP39 mnemonic.
// The function follows BIP84 standard with derivation path m/84'/2'/0'/0/0.
// It returns a Bech32 address (starts with "ltc1") for Litecoin mainnet.
//
// Parameters:
//   - mnemonic: A valid BIP39 mnemonic phrase
//   - bip39Passphrase: Optional BIP39 passphrase (empty string if not used)
//
// Returns:
//   - address: The Litecoin P2WPKH address (starts with "ltc1")
//   - error: Any error that occurred during derivation
func DeriveLitecoinAddress(mnemonic string, bip39Passphrase string) (string, error) {
	// Derive at m/84'/2'/0'/0/0 (BIP84 native SegWit, coin type 2 = Litecoin)
	pubKeyHash, err := deriveBIPAddress(mnemonic, bip39Passphrase, 84, 2) //nolint:mnd
	if err != nil {
		return "", fmt.Errorf("failed to derive Litecoin key: %w", err)
	}

	// Encode as Bech32 with HRP "ltc" and witness version 0
	addr, err := encodeBech32Address("ltc", 0, pubKeyHash)
	if err != nil {
		return "", fmt.Errorf("failed to encode Litecoin address: %w", err)
	}

	return addr, nil
}

// DeriveDogecoinAddress derives a Dogecoin P2PKH address from a BIP39 mnemonic.
// The function follows BIP44 standard with derivation path m/44'/3'/0'/0/0.
// It returns a Base58Check address (starts with "D") for Dogecoin mainnet.
//
// Parameters:
//   - mnemonic: A valid BIP39 mnemonic phrase
//   - bip39Passphrase: Optional BIP39 passphrase (empty string if not used)
//
// Returns:
//   - address: The Dogecoin P2PKH address (starts with "D")
//   - error: Any error that occurred during derivation
func DeriveDogecoinAddress(mnemonic string, bip39Passphrase string) (string, error) {
	// Derive at m/44'/3'/0'/0/0 (coin type 3 = Dogecoin)
	pubKeyHash, err := deriveBIP44Address(mnemonic, bip39Passphrase, 3) //nolint:mnd
	if err != nil {
		return "", fmt.Errorf("failed to derive Dogecoin key: %w", err)
	}

	// Encode as Base58Check with version byte 0x1E (Dogecoin mainnet P2PKH, produces "D...")
	return encodeBase58Check(0x1E, pubKeyHash), nil //nolint:mnd
}

// zcashMainnetP2PKHVersion is the 2-byte Base58Check version for Zcash mainnet transparent P2PKH (t1).
// Per Zcash chainparams: base58Prefixes[PUBKEY_ADDRESS] = {0x1C, 0xB8}.
const (
	zcashP2PKHVersionByte0 = 0x1C
	zcashP2PKHVersionByte1 = 0xB8
)

// DeriveZcashAddress derives a Zcash transparent P2PKH (t1) address from a BIP39 mnemonic.
// The function follows BIP44 standard with derivation path m/44'/133'/0'/0/0 (coin type 133 = Zcash per SLIP-0044).
// It returns a Base58Check address (starts with "t1") for Zcash mainnet.
//
// Parameters:
//   - mnemonic: A valid BIP39 mnemonic phrase
//   - bip39Passphrase: Optional BIP39 passphrase (empty string if not used)
//
// Returns:
//   - address: The Zcash transparent P2PKH address (starts with "t1")
//   - error: Any error that occurred during derivation
func DeriveZcashAddress(mnemonic string, bip39Passphrase string) (string, error) {
	// Derive at m/44'/133'/0'/0/0 (coin type 133 = Zcash)
	pubKeyHash, err := deriveBIP44Address(mnemonic, bip39Passphrase, 133) //nolint:mnd
	if err != nil {
		return "", fmt.Errorf("failed to derive Zcash key: %w", err)
	}

	// Encode as Base58Check with 2-byte version (Zcash mainnet P2PKH, produces "t1...")
	version := []byte{zcashP2PKHVersionByte0, zcashP2PKHVersionByte1}
	return encodeBase58CheckVersionBytes(version, pubKeyHash), nil
}

// rippleAlphabet is the custom Base58 alphabet used by the XRP Ledger.
const rippleAlphabet = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz"

// DeriveRippleAddress derives an XRP Ledger address from a BIP39 mnemonic.
// The function follows BIP44 standard with derivation path m/44'/144'/0'/0/0.
// It returns a Ripple Base58Check address (starts with "r").
//
// Parameters:
//   - mnemonic: A valid BIP39 mnemonic phrase
//   - bip39Passphrase: Optional BIP39 passphrase (empty string if not used)
//
// Returns:
//   - address: The XRP address (starts with "r")
//   - error: Any error that occurred during derivation
func DeriveRippleAddress(mnemonic string, bip39Passphrase string) (string, error) {
	// Derive at m/44'/144'/0'/0/0 (coin type 144 = XRP)
	pubKeyHash, err := deriveBIP44Address(mnemonic, bip39Passphrase, 144) //nolint:mnd
	if err != nil {
		return "", fmt.Errorf("failed to derive Ripple key: %w", err)
	}

	// Encode as Ripple Base58Check with version byte 0x00
	return encodeRippleBase58Check(0x00, pubKeyHash), nil //nolint:mnd
}

// encodeRippleBase58Check encodes data using Ripple's custom Base58Check format.
// It uses the same checksum scheme as Bitcoin (double SHA256) but a different alphabet.
func encodeRippleBase58Check(version byte, payload []byte) string {
	// Build versioned payload
	data := make([]byte, 0, 1+len(payload)+4) //nolint:mnd
	data = append(data, version)
	data = append(data, payload...)

	// Calculate checksum: first 4 bytes of double SHA256
	firstHash := sha256.Sum256(data)
	secondHash := sha256.Sum256(firstHash[:])
	checksum := secondHash[:4]
	data = append(data, checksum...)

	// Encode using Ripple's custom Base58 alphabet
	return encodeBase58WithAlphabet(data, rippleAlphabet)
}

// encodeBase58WithAlphabet encodes bytes using a custom Base58 alphabet.
func encodeBase58WithAlphabet(data []byte, alphabet string) string {
	// Use standard base58 encoding then translate the alphabet
	standardAlphabet := "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	encoded := base58.Encode(data)

	// Build translation table from standard to custom alphabet
	var result strings.Builder
	result.Grow(len(encoded))
	for _, c := range encoded {
		idx := strings.IndexRune(standardAlphabet, c)
		if idx >= 0 {
			result.WriteByte(alphabet[idx])
		}
	}

	return result.String()
}

// DeriveCosmosAddress derives a Cosmos (ATOM) address from a BIP39 mnemonic.
// The function follows BIP44 standard with derivation path m/44'/118'/0'/0/0.
// It returns a Bech32 address with the "cosmos" prefix (starts with "cosmos1").
//
// Parameters:
//   - mnemonic: A valid BIP39 mnemonic phrase
//   - bip39Passphrase: Optional BIP39 passphrase (empty string if not used)
//
// Returns:
//   - address: The Cosmos address (starts with "cosmos1")
//   - error: Any error that occurred during derivation
func DeriveCosmosAddress(mnemonic string, bip39Passphrase string) (string, error) {
	return deriveCosmosBech32Address(mnemonic, bip39Passphrase, 118, "cosmos") //nolint:mnd
}

// DeriveNobleAddress derives a Noble address from a BIP39 mnemonic.
// Noble uses the same key derivation as Cosmos (coin type 118) but with "noble" bech32 prefix.
//
// Parameters:
//   - mnemonic: A valid BIP39 mnemonic phrase
//   - bip39Passphrase: Optional BIP39 passphrase (empty string if not used)
//
// Returns:
//   - address: The Noble address (starts with "noble1")
//   - error: Any error that occurred during derivation
func DeriveNobleAddress(mnemonic string, bip39Passphrase string) (string, error) {
	return deriveCosmosBech32Address(mnemonic, bip39Passphrase, 118, "noble") //nolint:mnd
}

// deriveCosmosBech32Address derives a Cosmos-ecosystem Bech32 address.
// It uses secp256k1 at m/44'/coinType'/0'/0/0 and encodes the HASH160 of the
// compressed public key as Bech32 with the given human-readable prefix.
func deriveCosmosBech32Address(mnemonic string, bip39Passphrase string, coinType uint32, hrp string) (string, error) {
	// Derive the key at m/44'/coinType'/0'/0/0
	pubKeyHash, err := deriveBIP44Address(mnemonic, bip39Passphrase, coinType)
	if err != nil {
		return "", fmt.Errorf("failed to derive %s key: %w", hrp, err)
	}

	// Convert the 20-byte hash to 5-bit groups for bech32 encoding
	converted, err := bech32.ConvertBits(pubKeyHash, 8, 5, true) //nolint:mnd
	if err != nil {
		return "", fmt.Errorf("failed to convert bits for %s address: %w", hrp, err)
	}

	// Encode as bech32 (no witness version prefix for Cosmos)
	encoded, err := bech32.Encode(hrp, converted)
	if err != nil {
		return "", fmt.Errorf("failed to encode %s address: %w", hrp, err)
	}

	return encoded, nil
}

// DeriveStellarAddress derives a Stellar (XLM) address from a BIP39 mnemonic.
// The function follows SEP-0005 standard with derivation path m/44'/148'/0'
// using SLIP-0010 Ed25519 derivation.
// It returns a StrKey-encoded public key (starts with "G").
//
// Parameters:
//   - mnemonic: A valid BIP39 mnemonic phrase
//   - bip39Passphrase: Optional BIP39 passphrase (empty string if not used)
//
// Returns:
//   - address: The Stellar address (starts with "G")
//   - error: Any error that occurred during derivation
func DeriveStellarAddress(mnemonic string, bip39Passphrase string) (string, error) {
	// Validate mnemonic and convert to BIP39 seed with optional passphrase
	seed, err := bip39.NewSeedWithErrorChecking(mnemonic, bip39Passphrase)
	if err != nil {
		return "", fmt.Errorf("invalid mnemonic: %w", err)
	}

	// Derive Ed25519 key using SLIP-0010 at m/44'/148'/0' (SEP-0005)
	key := deriveEd25519Key(seed, []uint32{44, 148, 0})

	// Generate Ed25519 public key from the derived private key
	privateKey := ed25519.NewKeyFromSeed(key)
	publicKey := privateKey.Public().(ed25519.PublicKey)

	// Encode using Stellar StrKey format (version byte 0x30 = 'G' prefix for account ID)
	return encodeStellarStrKey(0x30, publicKey), nil //nolint:mnd
}

// encodeStellarStrKey encodes raw bytes using Stellar's StrKey format.
// StrKey = Base32(versionByte || payload || crc16_xmodem(versionByte || payload)).
func encodeStellarStrKey(version byte, payload []byte) string {
	// Build data: version byte + payload
	data := make([]byte, 0, 1+len(payload))
	data = append(data, version)
	data = append(data, payload...)

	// Calculate CRC16-XMODEM checksum
	checksum := crc16xmodem(data)
	checksumBytes := []byte{byte(checksum & 0xFF), byte(checksum >> 8)} //nolint:mnd

	// Append checksum (little-endian)
	data = append(data, checksumBytes...)

	// Encode as Base32 (no padding)
	return base32Encode(data)
}

// crc16xmodem calculates the CRC16-XMODEM checksum used by Stellar StrKey.
func crc16xmodem(data []byte) uint16 {
	crc := uint16(0x0000) //nolint:mnd
	for _, b := range data {
		crc ^= uint16(b) << 8 //nolint:mnd
		for i := 0; i < 8; i++ {
			if crc&0x8000 != 0 {
				crc = (crc << 1) ^ 0x1021 //nolint:mnd
			} else {
				crc <<= 1
			}
		}
	}
	return crc
}

// base32Encode encodes bytes using RFC 4648 Base32 without padding.
func base32Encode(data []byte) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	var result strings.Builder
	result.Grow((len(data)*8 + 4) / 5) //nolint:mnd

	bits := 0
	buffer := 0

	for _, b := range data {
		buffer = (buffer << 8) | int(b) //nolint:mnd
		bits += 8
		for bits >= 5 {
			bits -= 5
			result.WriteByte(alphabet[(buffer>>bits)&0x1F])
		}
	}

	// Handle remaining bits
	if bits > 0 {
		result.WriteByte(alphabet[(buffer<<(5-bits))&0x1F]) //nolint:mnd
	}

	return result.String()
}

// DeriveSuiAddress derives a Sui address from a BIP39 mnemonic.
// The function follows SLIP-0010 Ed25519 derivation with path m/44'/784'/0'/0'/0'.
// It returns an address formatted as "0x" + hex(Blake2b-256(0x00 || pubkey)).
//
// Parameters:
//   - mnemonic: A valid BIP39 mnemonic phrase
//   - bip39Passphrase: Optional BIP39 passphrase (empty string if not used)
//
// Returns:
//   - address: The Sui address (starts with "0x")
//   - error: Any error that occurred during derivation
func DeriveSuiAddress(mnemonic string, bip39Passphrase string) (string, error) {
	// Validate mnemonic and convert to BIP39 seed with optional passphrase
	seed, err := bip39.NewSeedWithErrorChecking(mnemonic, bip39Passphrase)
	if err != nil {
		return "", fmt.Errorf("invalid mnemonic: %w", err)
	}

	// Derive Ed25519 key using SLIP-0010 at m/44'/784'/0'/0'/0'
	key := deriveEd25519Key(seed, []uint32{44, 784, 0, 0, 0})

	// Generate Ed25519 public key from the derived private key
	privateKey := ed25519.NewKeyFromSeed(key)
	publicKey := privateKey.Public().(ed25519.PublicKey)

	// Sui address = Blake2b-256(flag_byte || public_key)
	// Flag byte 0x00 indicates Ed25519 scheme
	payload := make([]byte, 0, 1+len(publicKey))
	payload = append(payload, 0x00) //nolint:mnd // Ed25519 flag byte
	payload = append(payload, publicKey...)

	hash := blake2b.Sum256(payload)

	return fmt.Sprintf("0x%s", hex.EncodeToString(hash[:])), nil
}

// torOnionVersion is the Tor v3 hidden service version byte used in the onion
// address checksum and encoding.
const torOnionVersion = byte(0x03)

// torSecretKeyHeader is the 32-byte magic prefix Tor expects at the start of
// every hs_ed25519_secret_key file (29 ASCII chars + 3 NUL padding bytes).
const torSecretKeyHeader = "== ed25519v1-secret: type0 ==\x00\x00\x00" //#nosec G101 -- file-format magic prefix, not a credential

// torPublicKeyHeader is the 32-byte magic prefix Tor expects at the start of
// every hs_ed25519_public_key file (29 ASCII chars + 3 NUL padding bytes).
const torPublicKeyHeader = "== ed25519v1-public: type0 ==\x00\x00\x00"

// OnionServiceKeys holds all the material needed to deploy a Tor v3 hidden
// service derived from an Ed25519 SSH key.
type OnionServiceKeys struct {
	// OnionAddress is the 56-character v3 .onion hostname, e.g.
	// "xyz...xyz.onion". This is the public identity of the hidden service.
	OnionAddress string

	// PrivateKeyFile is the binary content to write as hs_ed25519_secret_key
	// (96 bytes: 32-byte Tor header + 64-byte expanded Ed25519 private key).
	PrivateKeyFile []byte

	// PublicKeyFile is the binary content to write as hs_ed25519_public_key
	// (64 bytes: 32-byte Tor header + 32-byte Ed25519 public key).
	PublicKeyFile []byte

	// HostnameFile is the content to write as hostname (onion address + "\n").
	HostnameFile []byte
}

// DeriveOnionServiceKeys deterministically derives a Tor v3 hidden service
// identity from an Ed25519 SSH private key.
//
// Derivation follows the same domain-separation pattern used throughout this
// package: a 32-byte sub-seed is produced by SHA-256("seedify:tor:v3:" ||
// key.Seed()), then an Ed25519 sub-key is created from that sub-seed. The
// sub-key is independent of all other derived keys (RSA, DKIM, PGP) because
// each uses a distinct label.
//
// The returned OnionServiceKeys contains:
//   - OnionAddress: the 56-char v3 .onion hostname (ready to share publicly)
//   - PrivateKeyFile: write to <HiddenServiceDir>/hs_ed25519_secret_key
//   - PublicKeyFile: write to <HiddenServiceDir>/hs_ed25519_public_key
//   - HostnameFile: write to <HiddenServiceDir>/hostname
//
// Security note: the derived hidden service key is cryptographically linked to
// the source SSH key. Compromising either compromises both.
func DeriveOnionServiceKeys(key *ed25519.PrivateKey) (*OnionServiceKeys, error) {
	// Domain-separate the source key seed so the Tor sub-key is independent of
	// all other sub-keys derived by seedify (RSA, DKIM, PGP, etc.).
	label := []byte("seedify:tor:v3:")
	input := make([]byte, len(label)+len(key.Seed()))
	copy(input, label)
	copy(input[len(label):], key.Seed())
	subSeed := sha256.Sum256(input)

	// Derive the hidden service Ed25519 key pair from the sub-seed.
	torPrivKey := ed25519.NewKeyFromSeed(subSeed[:])
	pubKey := torPrivKey.Public().(ed25519.PublicKey)

	// Compute the "expanded" 64-byte private key that Tor stores in
	// hs_ed25519_secret_key. This is the standard Ed25519 key expansion from
	// RFC 8032: SHA-512 of the seed with three bits clamped.
	expandedArr := sha512.Sum512(subSeed[:])
	expandedArr[0] &= 248  // clear lowest 3 bits (cofactor)
	expandedArr[31] &= 127 // clear highest bit
	expandedArr[31] |= 64  // set second-highest bit

	// Compute the v3 onion address checksum.
	// Per the Tor spec (rend-spec-v3.txt §6):
	//   checksum = SHA3-256(".onion checksum" || pubkey || version)[:2]
	//   onion    = base32lower(pubkey || checksum || version) + ".onion"
	checksumInput := make([]byte, 0, 15+ed25519.PublicKeySize+1)
	checksumInput = append(checksumInput, []byte(".onion checksum")...)
	checksumInput = append(checksumInput, pubKey...)
	checksumInput = append(checksumInput, torOnionVersion)
	checksumHash := sha3.Sum256(checksumInput)

	// Assemble the 35-byte payload for base32 encoding (56 chars, no padding).
	addrBytes := make([]byte, 0, ed25519.PublicKeySize+2+1)
	addrBytes = append(addrBytes, pubKey...)
	addrBytes = append(addrBytes, checksumHash[:2]...)
	addrBytes = append(addrBytes, torOnionVersion)

	onionAddr := strings.ToLower(base32.StdEncoding.EncodeToString(addrBytes)) + ".onion"

	// Build the hs_ed25519_secret_key file: 32-byte header + 64-byte expanded key.
	privFile := make([]byte, 0, len(torSecretKeyHeader)+len(expandedArr))
	privFile = append(privFile, []byte(torSecretKeyHeader)...)
	privFile = append(privFile, expandedArr[:]...)

	// Build the hs_ed25519_public_key file: 32-byte header + 32-byte public key.
	pubFile := make([]byte, 0, len(torPublicKeyHeader)+ed25519.PublicKeySize)
	pubFile = append(pubFile, []byte(torPublicKeyHeader)...)
	pubFile = append(pubFile, pubKey...)

	return &OnionServiceKeys{
		OnionAddress:   onionAddr,
		PrivateKeyFile: privFile,
		PublicKeyFile:  pubFile,
		HostnameFile:   []byte(onionAddr + "\n"),
	}, nil
}
