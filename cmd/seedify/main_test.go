// Package main provides tests for the seedify CLI.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ZenTenApp/seedify"
	nostrpkg "github.com/nbd-wtf/go-nostr"
	"golang.org/x/crypto/ssh"
)

// TestBuildWordCounts verifies that buildWordCounts produces the correct ordered slices
// for every combination of chain-derivation flags.
func TestBuildWordCounts(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		bitcoin     bool
		ethereum    bool
		zcash       bool
		solana      bool
		tron        bool
		nostrFlag   bool
		monero      bool
		polyseedAll bool
		wantCounts  []int
	}{
		{
			name:       "no flags — empty",
			wantCounts: nil,
		},
		{
			name:       "--bdx only — no polyseed needed",
			wantCounts: nil,
		},
		{
			name:       "--xmr-legacy only — no polyseed needed",
			wantCounts: nil,
		},
		{
			name:       "--xmr (polyseed) adds 16",
			monero:     true,
			wantCounts: []int{16},
		},
		{
			name:        "--all-polyseeds adds 16",
			polyseedAll: true,
			wantCounts:  []int{16},
		},
		{
			name:       "--btc adds 12 and 24",
			bitcoin:    true,
			wantCounts: []int{12, 24},
		},
		{
			name:       "--nostr adds 24",
			nostrFlag:  true,
			wantCounts: []int{24},
		},
		{
			name:       "--eth adds 24",
			ethereum:   true,
			wantCounts: []int{24},
		},
		{
			name:       "--sol adds 24",
			solana:     true,
			wantCounts: []int{24},
		},
		{
			name:       "--btc --xmr adds 12, 16, 24",
			bitcoin:    true,
			monero:     true,
			wantCounts: []int{12, 16, 24},
		},
		{
			name:       "--btc --eth --nostr adds 12 and 24 (no duplicates)",
			bitcoin:    true,
			ethereum:   true,
			nostrFlag:  true,
			wantCounts: []int{12, 24},
		},
		{
			name:       "--nostr was previously missing from --full --nostr word counts",
			nostrFlag:  true,
			wantCounts: []int{24},
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := buildWordCounts(tc.bitcoin, tc.ethereum, tc.zcash, tc.solana, tc.tron, tc.nostrFlag, tc.monero, tc.polyseedAll)
			if len(got) != len(tc.wantCounts) {
				t.Fatalf("buildWordCounts = %v, want %v", got, tc.wantCounts)
			}
			for i := range got {
				if got[i] != tc.wantCounts[i] {
					t.Fatalf("buildWordCounts[%d] = %d, want %d (full: %v)", i, got[i], tc.wantCounts[i], got)
				}
			}
		})
	}
}

// testKeyWithPassphrase creates a temporary password-protected Ed25519 SSH key
// in a temp directory and returns the file path. The key is cleaned up when the
// test ends via t.TempDir.
func testKeyWithPassphrase(t *testing.T, passphrase string) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	pemBlock, err := ssh.MarshalPrivateKeyWithPassphrase(priv, "", []byte(passphrase))
	if err != nil {
		t.Fatalf("marshal private key with passphrase: %v", err)
	}
	keyBytes := pem.EncodeToMemory(pemBlock)
	path := filepath.Join(t.TempDir(), "id_ed25519")
	if err := os.WriteFile(path, keyBytes, 0o600); err != nil {
		t.Fatalf("write key file: %v", err)
	}
	return path
}

// runSeedifyWithPassphrase runs the seedify binary at binaryPath with the given args,
// injecting passphrase via the SEEDIFY_TEST_PASSPHRASE mechanism.
// It relies on expect(1) being available.
func runSeedifyWithPassphrase(t *testing.T, binaryPath, passphrase, keyPath string, args ...string) (string, error) {
	t.Helper()
	if _, err := exec.LookPath("expect"); err != nil {
		t.Skip("expect(1) not available; skipping subprocess test")
	}

	allArgs := append([]string{keyPath}, args...)
	argStr := `"` + strings.Join(allArgs, `" "`) + `"`
	script := `set timeout 15
spawn ` + binaryPath + ` ` + argStr + `
expect {
  "Enter the passphrase" { send "` + passphrase + `\r"; exp_continue }
  eof
}
`
	cmd := exec.Command("expect")
	cmd.Stdin = strings.NewReader(script)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func TestZentenProfilePublishEntriesDefaultIncludesAllLabels(t *testing.T) {
	t.Parallel()

	record := dnsRecord{
		SSHEd25519:    "ssh-pub",
		Bitcoin:       "bc1example",
		SilentPayment: "sp1example",
		Litecoin:      "ltc1example",
		Ethereum:      "0xeth",
		HyperEVM:      "0xhype",
	}

	got := zentenProfilePublishEntries(record, "")
	want := []nip78Entry{
		{TagName: "ssh-ed25519", Value: "ssh-pub"},
		{TagName: "bitcoin", Value: "bc1example"},
		{TagName: "silentpayment", Value: "sp1example"},
		{TagName: "litecoin", Value: "ltc1example"},
		{TagName: "ethereum", Value: "0xeth"},
		{TagName: "hyperevm", Value: "0xhype"},
	}

	if len(got) != len(want) {
		t.Fatalf("zentenProfilePublishEntries returned %d entries, want %d: %#v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("zentenProfilePublishEntries[%d] = %#v, want %#v", i, got[i], want[i])
		}
	}
}

func TestZentenProfilePublishEntriesFiltersBlockchains(t *testing.T) {
	t.Parallel()

	record := dnsRecord{
		SSHEd25519:    "ssh-pub",
		Bitcoin:       "bc1example",
		SilentPayment: "sp1example",
		PayNym:        "PM8Texample",
		Litecoin:      "ltc1example",
		Monero:        "4example",
		Ethereum:      "0xeth",
		Solana:        "solexample",
	}

	got := zentenProfilePublishEntries(record, "silentpayment, ethereum,solana")
	want := []nip78Entry{
		{TagName: "silentpayment", Value: "sp1example"},
		{TagName: "ethereum", Value: "0xeth"},
		{TagName: "solana", Value: "solexample"},
	}

	if len(got) != len(want) {
		t.Fatalf("zentenProfilePublishEntries returned %d entries, want %d: %#v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("zentenProfilePublishEntries[%d] = %#v, want %#v", i, got[i], want[i])
		}
	}
}

func TestNostrRateLimitErrorDetection(t *testing.T) {
	t.Parallel()

	if !isNostrRateLimitError(errors.New("msg: rate-limited: you are noting too much")) {
		t.Fatal("expected damus rate-limit message to be detected")
	}
	if !isNostrRateLimitError(errors.New("rate limited by relay")) {
		t.Fatal("expected rate limited message to be detected")
	}
	if isNostrRateLimitError(errors.New("invalid: blocked")) {
		t.Fatal("did not expect non-rate-limit message to be detected")
	}
}

func TestNostrPublishBackoff(t *testing.T) {
	t.Parallel()

	tests := []struct {
		attempt int
		want    time.Duration
	}{
		{attempt: 1, want: 5 * time.Second},
		{attempt: 2, want: 15 * time.Second},
		{attempt: 3, want: 30 * time.Second},
		{attempt: 4, want: 30 * time.Second},
	}

	for _, tt := range tests {
		if got := nostrPublishBackoff(tt.attempt); got != tt.want {
			t.Fatalf("nostrPublishBackoff(%d) = %s, want %s", tt.attempt, got, tt.want)
		}
	}
}

func TestBuildZentenProfileEvents(t *testing.T) {
	t.Parallel()

	privKey := nostrpkg.GeneratePrivateKey()
	pubKey, err := nostrpkg.GetPublicKey(privKey)
	if err != nil {
		t.Fatalf("get public key: %v", err)
	}

	nostrKeys := &seedify.NostrKeys{PubKeyHex: pubKey, PrivKeyHex: privKey}
	record := &dnsRecord{Bitcoin: "bc1example", Ethereum: "0xexample"}
	events, err := buildZentenProfileEvents(record, nostrKeys, "ethereum")
	if err != nil {
		t.Fatalf("buildZentenProfileEvents: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("buildZentenProfileEvents returned %d events, want 1", len(events))
	}

	ethereum := events[0]
	if ethereum.Kind != kindNIP78 || ethereum.Content != "0xexample" {
		t.Fatalf("ethereum event kind/content = %d/%q, want %d/0xexample", ethereum.Kind, ethereum.Content, kindNIP78)
	}
	if len(ethereum.Tags) != 2 || len(ethereum.Tags[0]) != 2 || len(ethereum.Tags[1]) != 2 {
		t.Fatalf("ethereum tags = %#v", ethereum.Tags)
	}
	if ethereum.Tags[0][0] != "d" || ethereum.Tags[0][1] != "ethereum" || ethereum.Tags[1][0] != "i" || ethereum.Tags[1][1] != zentenProfileITag {
		t.Fatalf("ethereum tags = %#v", ethereum.Tags)
	}
}

func TestZentenProfileRandomIndex(t *testing.T) {
	t.Parallel()

	for range 100 {
		got, err := zentenProfileRandomIndex(1, 9)
		if err != nil {
			t.Fatalf("zentenProfileRandomIndex: %v", err)
		}
		if got < 1 || got > 9 {
			t.Fatalf("zentenProfileRandomIndex returned %d, want 1..9", got)
		}
	}

	got, err := zentenProfileRandomIndex(7, 7)
	if err != nil {
		t.Fatalf("zentenProfileRandomIndex singleton: %v", err)
	}
	if got != 7 {
		t.Fatalf("zentenProfileRandomIndex singleton returned %d, want 7", got)
	}
}

func TestZentenProfileBitcoinAddressUsesRandomIndex1To99(t *testing.T) {
	t.Parallel()

	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	mnemonic, err := seedify.ToMnemonicWithLength(&key, 24, "", false, 0) //nolint:mnd
	if err != nil {
		t.Fatalf("mnemonic: %v", err)
	}

	addr, index, err := zentenProfileBitcoinAddress(mnemonic)
	if err != nil {
		t.Fatalf("zentenProfileBitcoinAddress: %v", err)
	}
	if index < 1 || index > zentenProfileBitcoinDailyAddressMax {
		t.Fatalf("bitcoin index = %d, want 1..%d", index, zentenProfileBitcoinDailyAddressMax)
	}
	wantAddr, err := seedify.DeriveBitcoinAddressNativeSegwitAtIndex(mnemonic, "", index)
	if err != nil {
		t.Fatalf("derive expected bitcoin address: %v", err)
	}
	if addr != wantAddr {
		t.Fatalf("bitcoin address = %s, want index %d address %s", addr, index, wantAddr)
	}
}

func TestZentenProfileMoneroUsesCurrentDaySubaddress1To9(t *testing.T) {
	t.Parallel()

	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	date := time.Date(2026, time.June, 19, 0, 0, 0, 0, time.UTC)
	mnemonic, err := seedify.ToMnemonicWithLength(&key, 16, "", false, birthdayFromDate(date)) //nolint:mnd
	if err != nil {
		t.Fatalf("polyseed mnemonic: %v", err)
	}

	addr, index, err := zentenProfileMoneroSubaddress(mnemonic)
	if err != nil {
		t.Fatalf("zentenProfileMoneroSubaddress: %v", err)
	}
	if index < 1 || index > zentenProfileMoneroDailySubaddressMax {
		t.Fatalf("monero index = %d, want 1..%d", index, zentenProfileMoneroDailySubaddressMax)
	}
	primaryAddr, err := seedify.DeriveMoneroAddress(mnemonic)
	if err != nil {
		t.Fatalf("derive primary monero address: %v", err)
	}
	if addr == primaryAddr {
		t.Fatalf("monero address = primary address %s, want subaddress", addr)
	}
	wantAddr, err := seedify.DeriveMoneroSubaddressAtIndex(mnemonic, index-1)
	if err != nil {
		t.Fatalf("derive expected monero subaddress: %v", err)
	}
	if addr != wantAddr {
		t.Fatalf("monero address = %s, want subaddress %d %s", addr, index, wantAddr)
	}
}

// TestCLIOutput_ChainFlagsOmitPreamble verifies that targeted chain-flag invocations
// omit the SSH/Tor/I2P preamble and print only the requested data.
func TestCLIOutput_ChainFlagsOmitPreamble(t *testing.T) {
	// Build the binary into a temp directory for subprocess tests.
	binDir := t.TempDir()
	binPath := filepath.Join(binDir, "seedify")
	buildCmd := exec.Command("go", "build", "-o", binPath, ".")
	buildCmd.Dir = filepath.Join("..") // cmd/seedify
	// Resolve working directory relative to test file location.
	buildCmd.Dir = "."
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, out)
	}

	const pass = "testpass"
	keyPath := testKeyWithPassphrase(t, pass)

	tests := []struct {
		name        string
		args        []string
		mustContain []string
		mustAbsent  []string
	}{
		{
			name:        "--bdx emits only BDX seed and addresses",
			args:        []string{"--bdx"},
			mustContain: []string{"[25 word beldex (bdx) seed]", "[beldex addresses from 25 word seed]"},
			mustAbsent:  []string{"BEGIN OPENSSH PUBLIC KEY", "TOR ONION ADDRESS", "I2P DESTINATION", "[16 word seed phrase"},
		},
		{
			name:        "--xmr includes polyseed and legacy 25-word seed in polyseed section",
			args:        []string{"--xmr"},
			mustContain: []string{"[16 word seed phrase", "[monero addresses from 16 word polyseed", "[25 word monero legacy seed]", "[monero addresses from 25 word legacy seed]"},
			mustAbsent:  []string{"BEGIN OPENSSH PUBLIC KEY", "TOR ONION ADDRESS", "[monero addresses from 25 word legacy seed ("},
		},
		{
			name:        "--xmr-legacy emits only Monero legacy seed and addresses",
			args:        []string{"--xmr-legacy"},
			mustContain: []string{"[25 word monero legacy seed]", "[monero addresses from 25 word legacy seed]"},
			mustAbsent:  []string{"BEGIN OPENSSH PUBLIC KEY", "TOR ONION ADDRESS", "[16 word seed phrase"},
		},
		{
			name:        "--words 12 emits only 12-word phrase",
			args:        []string{"--words", "12"},
			mustContain: []string{"[12 word seed phrase]"},
			mustAbsent:  []string{"BEGIN OPENSSH PUBLIC KEY", "TOR ONION ADDRESS", "[24 word seed phrase]"},
		},
		{
			name:        "--nostr emits nostr keys but no preamble",
			args:        []string{"--nostr"},
			mustContain: []string{"[nostr keys from 24 word seed]", "npub1"},
			mustAbsent:  []string{"BEGIN OPENSSH PUBLIC KEY", "TOR ONION ADDRESS"},
		},
		{
			name:        "--full shows preamble",
			args:        []string{"--full"},
			mustContain: []string{"BEGIN OPENSSH PUBLIC KEY", "TOR ONION ADDRESS", "I2P DESTINATION"},
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			out, err := runSeedifyWithPassphrase(t, binPath, pass, keyPath, tc.args...)
			if err != nil {
				t.Fatalf("seedify exited with error: %v\noutput:\n%s", err, out)
			}
			for _, want := range tc.mustContain {
				if !strings.Contains(out, want) {
					t.Errorf("output missing %q\nfull output:\n%s", want, out)
				}
			}
			for _, absent := range tc.mustAbsent {
				if strings.Contains(out, absent) {
					t.Errorf("output should NOT contain %q\nfull output:\n%s", absent, out)
				}
			}
		})
	}
}
