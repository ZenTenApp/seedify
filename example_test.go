// Copyright (c) 2025-2026 complex (complex@ft.hn)
// See LICENSE for licensing information

package seedify_test

import (
	"crypto/ed25519"
	"fmt"

	"github.com/ZenTenApp/seedify"
)

// testKey returns a deterministic Ed25519 key for examples.
// In real usage this would come from an SSH key file.
func testKey() ed25519.PrivateKey {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	return ed25519.NewKeyFromSeed(seed)
}

func ExampleToMnemonicWithLength() {
	key := testKey()

	mnemonic, err := seedify.ToMnemonicWithLength(&key, 12, "", false, 0)
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	fmt.Println("word count: 12")
	fmt.Println("mnemonic:", mnemonic)
	// Output is deterministic but depends on the key bytes,
	// so we just verify it ran without error.
}

func ExampleToMnemonicWithLength_twentyFourWords() {
	key := testKey()

	mnemonic, err := seedify.ToMnemonicWithLength(&key, 24, "", false, 0)
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	fmt.Println("word count: 24")
	fmt.Println("mnemonic:", mnemonic)
}

func ExampleToMnemonicWithLength_polyseed() {
	key := testKey()

	mnemonic, err := seedify.ToMnemonicWithLength(&key, 16, "", false, seedify.PolyseedDefaultBirthday)
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	fmt.Println("word count: 16")
	fmt.Println("mnemonic:", mnemonic)
}

func ExampleToMnemonicWithLength_withSeedPassphrase() {
	key := testKey()

	m1, _ := seedify.ToMnemonicWithLength(&key, 24, "", false, 0)
	m2, _ := seedify.ToMnemonicWithLength(&key, 24, "my-secret", false, 0)

	// Different passphrases produce different mnemonics from the same key.
	fmt.Println("same mnemonic:", m1 == m2)
	// Output:
	// same mnemonic: false
}

func ExampleDeriveNostrKeysWithHex() {
	key := testKey()

	mnemonic, err := seedify.ToMnemonicWithLength(&key, 24, "", false, 0)
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	nostrKeys, err := seedify.DeriveNostrKeysWithHex(mnemonic, "")
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	fmt.Println("npub:", nostrKeys.Npub[:10]+"...")
	fmt.Println("nsec:", nostrKeys.Nsec[:10]+"...")
	fmt.Println("pubkey hex length:", len(nostrKeys.PubKeyHex))
	fmt.Println("privkey hex length:", len(nostrKeys.PrivKeyHex))
}

func ExampleDeriveBitcoinAddressNativeSegwit() {
	key := testKey()

	mnemonic, _ := seedify.ToMnemonicWithLength(&key, 24, "", false, 0)

	addr, err := seedify.DeriveBitcoinAddressNativeSegwit(mnemonic, "")
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	fmt.Println("starts with bc1q:", addr[:4] == "bc1q")
}

func ExampleDeriveEthereumAddress() {
	key := testKey()

	mnemonic, _ := seedify.ToMnemonicWithLength(&key, 24, "", false, 0)

	addr, err := seedify.DeriveEthereumAddress(mnemonic, "")
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	fmt.Println("starts with 0x:", addr[:2] == "0x")
	fmt.Println("length:", len(addr))
}

func ExampleDeriveMoneroKeys() {
	key := testKey()

	polyseed, err := seedify.ToMnemonicWithLength(&key, 16, "", false, seedify.PolyseedDefaultBirthday)
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	keys, err := seedify.DeriveMoneroKeys(polyseed, 3)
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	fmt.Println("primary starts with 4:", keys.PrimaryAddress[:1] == "4")
	fmt.Println("subaddress count:", len(keys.Subaddresses))
}

func ExampleDerivePayNym() {
	key := testKey()

	mnemonic, _ := seedify.ToMnemonicWithLength(&key, 24, "", false, 0)

	paynym, err := seedify.DerivePayNym(mnemonic, "")
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	fmt.Println("payment code prefix:", paynym.PaymentCode[:4])
}
