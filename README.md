# seedify

[![Go Reference](https://pkg.go.dev/badge/github.com/ZenTenApp/seedify.svg)](https://pkg.go.dev/github.com/ZenTenApp/seedify)
[![Build](https://github.com/ZenTenApp/seedify/actions/workflows/build.yml/badge.svg)](https://github.com/ZenTenApp/seedify/actions/workflows/build.yml)
[![Lint](https://github.com/ZenTenApp/seedify/actions/workflows/lint.yml/badge.svg)](https://github.com/ZenTenApp/seedify/actions/workflows/lint.yml)

Generate deterministic BIP-39 seed phrases from Ed25519 SSH keys, and derive
wallet addresses for 20+ blockchain networks.

seedify is both a **Go library** for programmatic use and a **CLI tool** for
interactive use.

## Features

- Generate BIP-39 mnemonic phrases (12, 15, 18, 21, or 24 words) from Ed25519 keys
- Generate 16-word [Polyseed](https://github.com/complex-gh/polyseed_go) phrases for Monero
- Derive wallet addresses and keys for 20+ chains from a single mnemonic
- Deterministic output -- same key always produces the same phrase
- Optional seed passphrase for additional entropy
- Brave Sync 25th-word support

### Supported Chains

| Chain | Address Type | Derivation |
|-------|-------------|------------|
| **Bitcoin** | Legacy P2PKH, SegWit P2SH-P2WPKH, Native SegWit P2WPKH, Silent Payments, Multisig (1-of-1) | BIP44/49/84/48/47 |
| **Nostr** | npub/nsec | NIP-06 (m/44'/1237'/0'/0/0) |
| **Monero** | Primary + subaddresses | Polyseed |
| **Ethereum** | EVM address | BIP44 (m/44'/60'/0'/0/0) |
| **Solana** | Ed25519 address | BIP44 (m/44'/501'/0'/0') |
| **Tron** | Base58Check address | BIP44 (m/44'/195'/0'/0/0) |
| **Litecoin** | Native SegWit | BIP84 |
| **Dogecoin** | P2PKH | BIP44 |
| **Zcash** | Transparent t-addr | BIP44 |
| **Cosmos** | Bech32 (cosmos1...) | BIP44 (m/44'/118'/0'/0/0) |
| **Noble** | Bech32 (noble1...) | BIP44 (m/44'/118'/0'/0/0) |
| **Stellar** | StrKey (G...) | BIP44 (m/44'/148'/0') |
| **Ripple** | Base58 (r...) | BIP44 (m/44'/144'/0'/0/0) |
| **Sui** | Hex (0x...) | BIP44 (m/44'/784'/0'/0'/0') |
| **Arbitrum, Avalanche, Base, BNB Chain, Cronos, Optimism, Polygon** | Same as Ethereum | BIP44 (m/44'/60'/0'/0/0) |

## Install

### As a Go Library

```sh
go get github.com/ZenTenApp/seedify@latest
```

### As a CLI Tool

**Homebrew** (macOS/Linux):

```sh
brew install ZenTenApp/tap/seedify
```

**Go install**:

```sh
go install github.com/ZenTenApp/seedify/cmd/seedify@latest
```

**Docker**:

```sh
docker run --rm -v ~/.ssh:/root/.ssh:ro ghcr.io/ZenTenApp/seedify /root/.ssh/id_ed25519
```

**Binary releases**: download from the
[Releases](https://github.com/ZenTenApp/seedify/releases) page.

## Library Usage

### Generate a Mnemonic from an Ed25519 Key

```go
package main

import (
	"crypto/ed25519"
	"fmt"
	"log"

	"github.com/ZenTenApp/seedify"
)

func main() {
	// Given an Ed25519 private key (e.g. parsed from an SSH key file):
	var key ed25519.PrivateKey // = ...

	// Generate a 24-word BIP-39 mnemonic
	mnemonic, err := seedify.ToMnemonicWithLength(&key, 24, "", false, 0)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(mnemonic)
}
```

### Mnemonic Generation

```go
// 12-word BIP-39
m12, _ := seedify.ToMnemonicWithLength(&key, 12, "", false, 0)

// 16-word Polyseed (with birthday timestamp for Monero)
m16, _ := seedify.ToMnemonicWithLength(&key, 16, "", false, seedify.PolyseedDefaultBirthday)

// 24-word BIP-39 with additional seed passphrase
m24, _ := seedify.ToMnemonicWithLength(&key, 24, "my-extra-entropy", false, 0)

// 24-word with a custom prefix (generates different words)
mPfx, _ := seedify.ToMnemonicWithPrefix(&key, 24, "", "wallet", 0)

// Brave Sync 25-word phrase (24 words + daily rotating 25th word)
brave, _ := seedify.ToMnemonicWithBraveSync(&key, "")

// Get the Brave Sync 25th word for today
word, _ := seedify.BraveSync25thWord()
```

Valid word counts: **12**, **15**, **16** (Polyseed), **18**, **21**, **24**.

### Derive Nostr Keys (NIP-06)

```go
// From a BIP-39 mnemonic -- returns npub, nsec, hex pubkey, hex privkey
keys, err := seedify.DeriveNostrKeysWithHex(mnemonic, "")
fmt.Println(keys.Npub)       // npub1...
fmt.Println(keys.Nsec)       // nsec1...
fmt.Println(keys.PubKeyHex)  // 64-char hex
fmt.Println(keys.PrivKeyHex) // 64-char hex

// Simpler variant returning only npub/nsec strings
npub, nsec, err := seedify.DeriveNostrKeys(mnemonic, "")

// Directly from an Ed25519 key (no mnemonic needed)
npub, nsec, err := seedify.DeriveNostrKeysFromEd25519(&key)
```

### Derive Bitcoin Addresses and Keys

```go
// Single addresses
legacy, _  := seedify.DeriveBitcoinAddress(mnemonic, "")              // 1...  (P2PKH, BIP44)
segwit, _  := seedify.DeriveBitcoinAddressSegwit(mnemonic, "")        // 3...  (P2SH-P2WPKH, BIP49)
native, _  := seedify.DeriveBitcoinAddressNativeSegwit(mnemonic, "")  // bc1q... (P2WPKH, BIP84)
sp, _      := seedify.DeriveSilentPaymentAddress(mnemonic, "")        // sp1...

// Address + WIF private key
legacyKeys, _ := seedify.DeriveBitcoinLegacyKeys(mnemonic, "")
fmt.Println(legacyKeys.Address)    // 1...
fmt.Println(legacyKeys.PrivateWIF) // 5... or K.../L...

segwitKeys, _      := seedify.DeriveBitcoinSegwitKeys(mnemonic, "")
nativeSegwitKeys, _ := seedify.DeriveBitcoinNativeSegwitKeys(mnemonic, "")

// Extended keys (xpub/xprv, ypub/yprv, zpub/zprv)
masterExt, _ := seedify.DeriveBitcoinMasterExtendedKeys(mnemonic, "")
legacyExt, _ := seedify.DeriveBitcoinLegacyExtendedKeys(mnemonic, "")
segwitExt, _ := seedify.DeriveBitcoinSegwitExtendedKeys(mnemonic, "")
nativeExt, _ := seedify.DeriveBitcoinNativeSegwitExtendedKeys(mnemonic, "")

// Master fingerprint (4-byte hex)
fingerprint, _ := seedify.DeriveBitcoinMasterFingerprint(mnemonic, "")

// Multisig 1-of-1 keys
msLegacy, _ := seedify.DeriveBitcoinMultisigLegacyKeys(mnemonic, "")
msSegwit, _ := seedify.DeriveBitcoinMultisigSegwitKeys(mnemonic, "")
msNative, _ := seedify.DeriveBitcoinMultisigNativeSegwitKeys(mnemonic, "")

// Multisig extended keys (Ypub/Yprv, Zpub/Zprv with xpub/xprv equivalents)
msLegacyExt, _ := seedify.DeriveBitcoinMultisigLegacyExtendedKeys(mnemonic, "")
msSegwitExt, _ := seedify.DeriveBitcoinMultisigSegwitExtendedKeys(mnemonic, "")
msNativeExt, _ := seedify.DeriveBitcoinMultisigNativeSegwitExtendedKeys(mnemonic, "")

// PayNym / BIP-47 payment code
paynym, _ := seedify.DerivePayNym(mnemonic, "")
fmt.Println(paynym.PaymentCode)         // PM8T...
fmt.Println(paynym.NotificationAddress) // 1...
```

### Derive Other Chain Addresses

```go
eth, _     := seedify.DeriveEthereumAddress(mnemonic, "")  // 0x...
sol, _     := seedify.DeriveSolanaAddress(mnemonic, "")     // Base58
tron, _    := seedify.DeriveTronAddress(mnemonic, "")       // T...
ltc, _     := seedify.DeriveLitecoinAddress(mnemonic, "")   // ltc1...
doge, _    := seedify.DeriveDogecoinAddress(mnemonic, "")   // D...
zec, _     := seedify.DeriveZcashAddress(mnemonic, "")      // t1...
xrp, _     := seedify.DeriveRippleAddress(mnemonic, "")     // r...
cosmos, _  := seedify.DeriveCosmosAddress(mnemonic, "")     // cosmos1...
noble, _   := seedify.DeriveNobleAddress(mnemonic, "")      // noble1...
xlm, _     := seedify.DeriveStellarAddress(mnemonic, "")    // G...
sui, _     := seedify.DeriveSuiAddress(mnemonic, "")        // 0x...
```

EVM-compatible chains (Arbitrum, Avalanche, Base, BNB Chain, Cronos, Optimism,
Polygon) share the same address as Ethereum -- call `DeriveEthereumAddress`.

### Derive Monero Addresses (from Polyseed)

```go
// Generate a 16-word Polyseed mnemonic first
polyseed, _ := seedify.ToMnemonicWithLength(&key, 16, "", false, seedify.PolyseedDefaultBirthday)

// Primary address
addr, _ := seedify.DeriveMoneroAddress(polyseed) // 4...

// Subaddress at a specific index
sub, _ := seedify.DeriveMoneroSubaddressAtIndex(polyseed, 1) // 8...

// Primary + multiple subaddresses in one call
keys, _ := seedify.DeriveMoneroKeys(polyseed, 5)
fmt.Println(keys.PrimaryAddress) // 4...
fmt.Println(keys.Subaddresses)   // [8..., 8..., 8..., 8..., 8...]
```

## API Reference

The full API documentation is available on
[pkg.go.dev](https://pkg.go.dev/github.com/ZenTenApp/seedify).

### Constants

| Constant | Description |
|----------|-------------|
| `PolyseedDefaultBirthday` | Default Polyseed birthday (1 Jan 2026 00:00 UTC). Use for deterministic 16-word output. Pass `0` for current time. |

### Types

| Type | Fields | Description |
|------|--------|-------------|
| `NostrKeys` | `Npub`, `Nsec`, `PubKeyHex`, `PrivKeyHex` | Nostr key pair in bech32 and hex formats |
| `BitcoinKeys` | `Address`, `PrivateWIF` | Bitcoin address with its WIF-encoded private key |
| `BitcoinExtendedKeys` | `ExtendedPublicKey`, `ExtendedPrivateKey` | Account-level extended keys (xpub/xprv, ypub/yprv, zpub/zprv) |
| `BitcoinMultisigExtendedKeys` | `ExtendedPublicKey`, `ExtendedPrivateKey`, `StandardPublicKey`, `StandardPrivateKey` | Multisig extended keys in both specific (Ypub/Zpub) and standard (xpub) formats |
| `PayNymKeys` | `PaymentCode`, `NotificationAddress` | BIP-47 payment code and notification address |
| `MoneroKeys` | `PrimaryAddress`, `Subaddresses` | Monero primary address and subaddresses |

### Functions

#### Mnemonic Generation

| Function | Description |
|----------|-------------|
| `ToMnemonicWithLength(key, wordCount, seedPassphrase, brave, birthday)` | Generate a mnemonic of the given word count (12/15/16/18/21/24) |
| `ToMnemonicWithPrefix(key, wordCount, seedPassphrase, prefix, birthday)` | Generate a mnemonic with a custom prefix for domain separation |
| `ToMnemonicWithBraveSync(key, seedPassphrase)` | Generate a 25-word Brave Sync phrase |
| `BraveSync25thWord()` | Get today's Brave Sync 25th word |
| `BraveSync25thWordForDate(date)` | Get the Brave Sync 25th word for a specific date |

#### Nostr (NIP-06)

| Function | Description |
|----------|-------------|
| `DeriveNostrKeysWithHex(mnemonic, bip39Passphrase)` | Derive full Nostr key set (npub, nsec, hex) from mnemonic |
| `DeriveNostrKeys(mnemonic, bip39Passphrase)` | Derive npub/nsec strings from mnemonic |
| `DeriveNostrKeysFromEd25519(key)` | Derive npub/nsec directly from an Ed25519 key |

#### Bitcoin

| Function | Description |
|----------|-------------|
| `DeriveBitcoinAddress(mnemonic, passphrase)` | Legacy P2PKH address (BIP44) |
| `DeriveBitcoinAddressSegwit(mnemonic, passphrase)` | SegWit P2SH-P2WPKH address (BIP49) |
| `DeriveBitcoinAddressNativeSegwit(mnemonic, passphrase)` | Native SegWit P2WPKH address (BIP84) |
| `DeriveBitcoinAddressNativeSegwitAtIndex(mnemonic, passphrase, index)` | Native SegWit address at a specific index |
| `DeriveSilentPaymentAddress(mnemonic, passphrase)` | BIP-352 Silent Payment address |
| `DeriveBitcoinLegacyKeys(mnemonic, passphrase)` | Legacy address + WIF key |
| `DeriveBitcoinSegwitKeys(mnemonic, passphrase)` | SegWit address + WIF key |
| `DeriveBitcoinNativeSegwitKeys(mnemonic, passphrase)` | Native SegWit address + WIF key |
| `DeriveBitcoinMasterFingerprint(mnemonic, passphrase)` | 4-byte master fingerprint (hex) |
| `DeriveBitcoinMasterExtendedKeys(mnemonic, passphrase)` | Master xpub/xprv at path m |
| `DeriveBitcoinLegacyExtendedKeys(mnemonic, passphrase)` | Account xpub/xprv (BIP44) |
| `DeriveBitcoinSegwitExtendedKeys(mnemonic, passphrase)` | Account ypub/yprv (BIP49) |
| `DeriveBitcoinNativeSegwitExtendedKeys(mnemonic, passphrase)` | Account zpub/zprv (BIP84) |
| `DeriveBitcoinMultisigLegacyKeys(mnemonic, passphrase)` | Multisig legacy address + WIF (BIP48) |
| `DeriveBitcoinMultisigSegwitKeys(mnemonic, passphrase)` | Multisig SegWit address + WIF (BIP48) |
| `DeriveBitcoinMultisigNativeSegwitKeys(mnemonic, passphrase)` | Multisig native SegWit address + WIF (BIP48) |
| `DeriveBitcoinMultisigLegacyExtendedKeys(mnemonic, passphrase)` | Multisig legacy xpub/xprv (BIP48) |
| `DeriveBitcoinMultisigSegwitExtendedKeys(mnemonic, passphrase)` | Multisig SegWit Ypub/Yprv + xpub/xprv (BIP48) |
| `DeriveBitcoinMultisigNativeSegwitExtendedKeys(mnemonic, passphrase)` | Multisig native SegWit Zpub/Zprv + xpub/xprv (BIP48) |
| `DerivePayNym(mnemonic, passphrase)` | BIP-47 PayNym payment code + notification address |

#### Monero

| Function | Description |
|----------|-------------|
| `DeriveMoneroAddress(mnemonic)` | Primary Monero address from a 16-word Polyseed |
| `DeriveMoneroSubaddressAtIndex(mnemonic, index)` | Monero subaddress at a given index |
| `DeriveMoneroKeys(mnemonic, numSubaddresses)` | Primary address + N subaddresses |

#### Other Chains

| Function | Description |
|----------|-------------|
| `DeriveEthereumAddress(mnemonic, passphrase)` | Ethereum / EVM address |
| `DeriveSolanaAddress(mnemonic, passphrase)` | Solana address |
| `DeriveTronAddress(mnemonic, passphrase)` | Tron address |
| `DeriveLitecoinAddress(mnemonic, passphrase)` | Litecoin native SegWit address |
| `DeriveDogecoinAddress(mnemonic, passphrase)` | Dogecoin address |
| `DeriveZcashAddress(mnemonic, passphrase)` | Zcash transparent address |
| `DeriveRippleAddress(mnemonic, passphrase)` | Ripple (XRP) address |
| `DeriveCosmosAddress(mnemonic, passphrase)` | Cosmos address |
| `DeriveNobleAddress(mnemonic, passphrase)` | Noble address |
| `DeriveStellarAddress(mnemonic, passphrase)` | Stellar address |
| `DeriveSuiAddress(mnemonic, passphrase)` | Sui address |

## CLI Usage

```
seedify <key-path> [flags]
```

```
seedify ~/.ssh/id_ed25519
seedify ~/.ssh/id_ed25519 --words 12
seedify ~/.ssh/id_ed25519 --words 12,24
seedify ~/.ssh/id_ed25519 --nostr
seedify ~/.ssh/id_ed25519 --btc --eth --sol
seedify ~/.ssh/id_ed25519 --full
seedify ~/.ssh/id_ed25519 --brave
seedify ~/.ssh/id_ed25519 --xmr --polyseed-year 2025
cat ~/.ssh/id_ed25519 | seedify --words 18
```

### Flags

| Flag | Description |
|------|-------------|
| `-w, --words` | Word counts to generate, comma-separated (12,15,16,18,21,24) |
| `--seed-passphrase` | Combine with SSH key seed for additional entropy |
| `--brave` | Generate 25-word Brave Sync phrase |
| `--full` | Print all word counts and all chain derivations |
| `--nostr` | Derive Nostr keys (npub/nsec) |
| `--btc` | Derive Bitcoin addresses |
| `--eth` | Derive Ethereum address |
| `--zec` | Derive Zcash address |
| `--sol` | Derive Solana address |
| `--tron` | Derive Tron address |
| `--xmr` | Derive Monero address from Polyseed |
| `--zenprofile` | Output public keys and addresses as DNS JSON |
| `--publish` | Publish NIP-78 event to relays (with `--zenprofile`) |
| `--polyseed-year` | Override Polyseed birthday year (default: current year) |
| `-l, --language` | Mnemonic language (default: en) |

### Security Tip

Add a leading space before the command to prevent it from being saved in your
shell history:

```
 seedify ~/.ssh/id_ed25519
```

Most shells (bash, zsh) ignore commands that start with a space when
`HISTCONTROL=ignorespace` or `HIST_IGNORE_SPACE` is set.

## Security Considerations

- **Password-protected keys only**: The CLI requires SSH keys to be
  password-protected. Unprotected keys are rejected.
- **One-way derivation**: Seed phrases cannot be used to recover the original
  SSH key. The derivation is intentionally irreversible.
- **Deterministic output**: The same key + passphrase always produces the same
  mnemonic. This means the mnemonic is only as secure as the SSH key and
  passphrase.
- **Seed passphrase**: Use `--seed-passphrase` (CLI) or the `seedPassphrase`
  parameter (library) to add entropy beyond the SSH key alone. Different
  passphrases produce completely different mnemonics.

## License

[MIT](LICENSE) -- Copyright (c) 2025-2026 complex (complex@ft.hn)
