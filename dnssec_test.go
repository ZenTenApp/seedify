package seedify

import (
	"crypto/ed25519"
	"strings"
	"testing"
)

func TestDeriveDNSSECKeypairDeterministic(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	key := ed25519.NewKeyFromSeed(seed)

	first, err := DeriveDNSSECKeypair(&key, "Example.COM", DNSSECAlgorithmRSASHA256, dnssecKSKFlags, 2048)
	if err != nil {
		t.Fatalf("derive first DNSSEC keypair: %v", err)
	}
	second, err := DeriveDNSSECKeypair(&key, "example.com.", DNSSECAlgorithmRSASHA256, dnssecKSKFlags, 2048)
	if err != nil {
		t.Fatalf("derive second DNSSEC keypair: %v", err)
	}

	if first.KeyTag != second.KeyTag {
		t.Fatalf("key tags differ: %d != %d", first.KeyTag, second.KeyTag)
	}
	if first.DNSKEYRecord != second.DNSKEYRecord {
		t.Fatalf("DNSKEY records differ")
	}
	if first.DSRecord != second.DSRecord {
		t.Fatalf("DS records differ")
	}
	if string(first.PrivateKeyFile) != string(second.PrivateKeyFile) {
		t.Fatalf("private key files differ")
	}
}

func TestDeriveDNSSECKeypairFormats(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(255 - i)
	}
	key := ed25519.NewKeyFromSeed(seed)

	pair, err := DeriveDNSSECKeypair(&key, "example.com", DNSSECAlgorithmRSASHA256, dnssecKSKFlags, 2048)
	if err != nil {
		t.Fatalf("derive DNSSEC keypair: %v", err)
	}

	if pair.Domain != "example.com." {
		t.Fatalf("unexpected domain: %q", pair.Domain)
	}
	if !strings.HasPrefix(pair.FileBase, "Kexample.com.+008+") {
		t.Fatalf("unexpected file base: %q", pair.FileBase)
	}
	if !strings.Contains(pair.DNSKEYRecord, " IN DNSKEY 257 3 8 ") {
		t.Fatalf("unexpected DNSKEY record: %q", pair.DNSKEYRecord)
	}
	if !strings.Contains(pair.DSRecord, " IN DS ") || !strings.Contains(pair.DSRecord, " 8 2 ") {
		t.Fatalf("unexpected DS record: %q", pair.DSRecord)
	}
	if !strings.Contains(string(pair.PrivateKeyFile), "Private-key-format: v1.3\nAlgorithm: 8 (RSASHA256)\n") {
		t.Fatalf("unexpected private key file:\n%s", pair.PrivateKeyFile)
	}
}

func TestDeriveDNSSECKeypairRejectsUnsupportedAlgorithm(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	key := ed25519.NewKeyFromSeed(seed)

	_, err := DeriveDNSSECKeypair(&key, "example.com", 15, dnssecKSKFlags, 2048)
	if err == nil {
		t.Fatal("expected unsupported algorithm error")
	}
}
