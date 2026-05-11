// derive_zcash derives a Zcash transparent (t1) address from a BIP39 mnemonic for testing.
//
// Usage:
//
//	go run ./scripts/derive_zcash "your 24 word seed phrase here"
//
// Or with stdin:
//
//	echo "your 24 word seed phrase" | go run ./scripts/derive_zcash
//
// Note: This derives a transparent t1 address (BIP44 m/44'/133'/0'/0/0).
// YWallet and other modern Zcash wallets use Unified Addresses (u1) or Sapling
// shielded addresses (zs1), which use ZIP-32 derivation—a different key tree.
// The t1 address will not match YWallet's u1 address for the same seed.
package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/ZenTenApp/seedify"
)

func main() {
	var mnemonic string

	if len(os.Args) > 1 {
		mnemonic = strings.Join(os.Args[1:], " ")
	} else {
		scanner := bufio.NewScanner(os.Stdin)
		if scanner.Scan() {
			mnemonic = strings.TrimSpace(scanner.Text())
		}
	}

	if mnemonic == "" {
		fmt.Fprintln(os.Stderr, "Usage: derive_zcash \"24 word seed phrase\"")
		fmt.Fprintln(os.Stderr, "   or: echo \"seed phrase\" | derive_zcash")
		os.Exit(1)
	}

	addr, err := seedify.DeriveZcashAddress(mnemonic, "")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(addr)
}
