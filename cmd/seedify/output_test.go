package main

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
)

func captureStdout(fn func()) string {
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		panic(err)
	}
	os.Stdout = w
	fn()
	_ = w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	_ = r.Close()
	return buf.String()
}

func TestCLIOut_PlainTextPreservesContent(t *testing.T) {
	t.Setenv("NO_COLOR", "1")

	o := newCLIOut()
	got := captureStdout(func() {
		o.Section("bitcoin addresses from 24 word seed")
		o.Blank()
		o.Field("bc1qtest", "native segwit P2WPKH - BIP84")
		o.Blank()
		o.Sensitive("word1 word2 word3")
		o.PEMBlock("12-WORD SEED PHRASE", "abandon abandon abandon", true)
	})

	for _, want := range []string{
		"[bitcoin addresses from 24 word seed]",
		"bc1qtest (native segwit P2WPKH - BIP84)",
		"word1 word2 word3",
		"-----BEGIN 12-WORD SEED PHRASE-----",
		"abandon abandon abandon",
		"-----END 12-WORD SEED PHRASE-----",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("output missing %q\nfull output:\n%s", want, got)
		}
	}
}

func TestCLIOut_PEMBlockDelimited(t *testing.T) {
	t.Setenv("NO_COLOR", "1")

	o := newCLIOut()
	got := captureStdout(func() {
		o.PEMBlockDelimited("24-WORD SEED PHRASE (charmbracelet/MELT)", "abandon abandon abandon", "=====", true)
	})

	for _, want := range []string{
		"=====BEGIN 24-WORD SEED PHRASE (charmbracelet/MELT)=====",
		"abandon abandon abandon",
		"=====END 24-WORD SEED PHRASE (charmbracelet/MELT)=====",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("output missing %q\nfull output:\n%s", want, got)
		}
	}
}

func TestCLIOut_AndroidJKSSecretsSection(t *testing.T) {
	t.Setenv("NO_COLOR", "1")

	o := newCLIOut()
	got := captureStdout(func() {
		o.AndroidJKSSecretsSection(
			"zenten-release.jks",
			"zenten",
			"store-pass",
			"store-pass",
			"QUJDRA==",
		)
	})

	for _, want := range []string{
		"[Android signing secrets]",
		"ANDROID_KEYSTORE_BASE64",
		"QUJDRA==",
		"is the JKS file — base64-encoded contents of zenten-release.jks",
		"ANDROID_KEY_ALIAS",
		"zenten",
		"chosen when you created the keystore",
		"ANDROID_STORE_PASSWORD",
		"store-pass",
		"cannot be extracted from the JKS",
		"ANDROID_KEY_PASSWORD",
		"same as the store password",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("output missing %q\nfull output:\n%s", want, got)
		}
	}
}

func TestCLIOut_TreeAndSubFields(t *testing.T) {
	t.Setenv("NO_COLOR", "1")

	o := newCLIOut()
	got := captureStdout(func() {
		o.TreeField("deadbeef", "hex")
		o.SubField("4addr", "subaddress 0,1")
		o.SensitiveTreeField("secret", "xprv")
	})

	for _, want := range []string{
		"└─ deadbeef (hex)",
		"> 4addr (subaddress 0,1)",
		"└─ secret (xprv)",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("output missing %q\nfull output:\n%s", want, got)
		}
	}
}

func TestCLIOut_NostrKeyBlock(t *testing.T) {
	t.Setenv("NO_COLOR", "1")

	o := newCLIOut()
	got := captureStdout(func() {
		o.NostrKeyBlock("npub1", "hexpub", "nsec1", "hexsec")
	})

	for _, want := range []string{
		"----- nPubKey / hexPubKey / nSecKey / hexSecKey -----",
		"npub1",
		"hexpub",
		"nsec1",
		"hexsec",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("output missing %q\nfull output:\n%s", want, got)
		}
	}
}

func TestCLIOut_LabeledBlock(t *testing.T) {
	t.Setenv("NO_COLOR", "1")

	o := newCLIOut()
	got := captureStdout(func() {
		o.LabeledBlock("I2P DESTINATION", []string{
			"B32 Address  : abc",
			"X25519 PrivKey (hex): dead",
		})
	})

	for _, want := range []string{
		"-----BEGIN I2P DESTINATION-----",
		"B32 Address  : abc",
		"-----END I2P DESTINATION-----",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("output missing %q\nfull output:\n%s", want, got)
		}
	}
}
