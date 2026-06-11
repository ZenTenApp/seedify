package seedify

import (
	"encoding/hex"
	"testing"

	"github.com/chekist32/go-monero/utils"
	"github.com/matryer/is"
)

// TestBeldexViewKeyDerivation verifies that the view private key derived from a
// mnemonic decoded via go-monero matches the view key reported by beldex-wallet-cli v7.
//
// CLI command used (beldex-wallet-cli v7.0.0-38e6f19fb):
//
//	./beldex-wallet-cli \
//	  --offline \
//	  --generate-new-wallet /tmp/test_wallet \
//	  --password ""
//
// The view key was taken directly from the "View key: ..." line in the CLI output.
//
//	Mnemonic:    looking tagged deity potato village september furnished ditch
//	             menu suede joyous present faulty ringing unfit certain
//	             fierce getting bobsled metro suture fazed unquoted venomous menu
//	View key:    d74c9efa3b232b02b71df2bd2eb5f1c449e7278e463a94c63df8fc361edf6c05
func TestBeldexViewKeyDerivation(t *testing.T) {
	is := is.New(t)

	const mnemonic = "looking tagged deity potato village september furnished ditch menu suede joyous present faulty ringing unfit certain fierce getting bobsled metro suture fazed unquoted venomous menu"
	const wantViewPriv = "d74c9efa3b232b02b71df2bd2eb5f1c449e7278e463a94c63df8fc361edf6c05"

	seed, err := utils.NewSeedMnemonic(mnemonic, utils.English)
	is.NoErr(err)

	gotViewPriv := hex.EncodeToString(seed.FullKeyPair().ViewKeyPair().PrivateKey().Bytes())
	is.Equal(gotViewPriv, wantViewPriv)
}
