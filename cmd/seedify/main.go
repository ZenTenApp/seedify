// Package main provides the seedify CLI tool for generating seed phrases from SSH keys.
package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/ZenTenApp/seedify"
	"github.com/charmbracelet/lipgloss"
	"github.com/mattn/go-isatty"
	"github.com/mattn/go-tty"
	"github.com/mdp/qrterminal/v3"
	mcobra "github.com/muesli/mango-cobra"
	"github.com/muesli/roff"
	nostrpkg "github.com/nbd-wtf/go-nostr"
	"github.com/spf13/cobra"
	"github.com/tyler-smith/go-bip39"
	"github.com/tyler-smith/go-bip39/wordlists"
	"github.com/youmark/pkcs8"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
	lang "golang.org/x/text/language"
	"golang.org/x/text/language/display"
)

const (
	maxWidth = 72

	// Polyseed birthday encoding constants from github.com/complex-gh/polyseed_go.
	// The library keeps these unexported, but seedify needs them to show the
	// beginning of the encoded birthday period in CLI labels.
	polyseedBirthdayEpochUnix = uint64(1635768000)
	polyseedBirthdayTimeStep  = uint64(2629746)

	kindNostrProfileMetadata = 0

	zentenProfileMoneroDailySubaddressMax = 9
	defaultXMRAddressCount                = 9
	zentenProfileBitcoinDailyAddressMax   = 99

	nostrPublishMaxRetries             = 3
	nostrPublishSecondRetryAttempt     = 2
	nostrPublishFirstRateLimitBackoff  = 5 * time.Second
	nostrPublishSecondRateLimitBackoff = 15 * time.Second
	nostrPublishMaxRateLimitBackoff    = 30 * time.Second
	nostrPublishTimeout                = 15 * time.Minute
)

// Populated at build time via -ldflags (set by GoReleaser and `go build -ldflags`).
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

var (
	baseStyle  = lipgloss.NewStyle().Margin(0, 0, 1, 2) //nolint:mnd
	red        = lipgloss.Color(completeColor("#FF4444", "196", "9"))
	errorStyle = baseStyle.
			Foreground(red).
			Background(lipgloss.AdaptiveColor{Light: completeColor("#FFEBEB", "255", "7"), Dark: completeColor("#2B1A1A", "235", "8")}).
			Padding(1, 2) //nolint:mnd

	language                 string
	wordCountStr             string
	seedPassphrase           string
	brainBunkerKDFRounds     int
	brainBunkerKeyPassphrase string
	bip39Passphrase          string
	configPath               string
	brave                    bool
	full                     bool
	nostr                    bool
	bitcoin                  bool
	ethereum                 bool
	zcash                    bool
	solana                   bool
	tron                     bool
	monero                   bool
	moneroLegacy             bool
	xmrSeedOffset            string
	beldex                   bool
	sshKeyQR                 bool
	zentenprofile            bool
	publishRelays            string
	blockchains              string
	polyseedYear             string
	polyseedMonth            string
	polyseedAll              bool

	// derive-key flags.
	deriveKeyToRSA           bool
	deriveKeyToDKIM          bool
	deriveKeyToDNSSEC        bool
	deriveKeyToOnion         bool
	deriveKeyToI2P           bool
	deriveKeyToWireGuard     bool
	deriveKeyPKCS8           bool
	deriveKeyToPGP           bool
	deriveKeyToJKS           bool
	deriveKeyPGPName         string
	deriveKeyPGPEmail        string
	deriveKeyJKSAlias        string
	deriveKeyJKSValidity     int
	deriveKeyJKSDN           string
	deriveKeyOutput          string
	deriveKeyBits            int
	deriveKeyDKIMSelector    string
	deriveKeyDKIMDomain      string
	deriveKeyDNSSECDomain    string
	deriveKeyDNSSECAlgorithm int
	deriveKeyDNSSECKSK       bool
	deriveKeyDNSSECZSK       bool
	deriveKeyReusePassphrase bool

	rootCmd = &cobra.Command{
		Use:   "seedify <key-path>",
		Short: "Generate a seed phrase from an SSH key",
		Long: `Generate a seed phrase from an SSH key.

Valid word counts are: 12, 15, 16, 18, 21, or 24.
- 12, 15, 18, 21, 24 words use BIP39 format
- 16 words use Polyseed format

By default, one 16-word Polyseed phrase is shown for the current year
(using January 1 as the birthday). Use --polyseed-year to override
the year and --polyseed-month (1-12) to override the month.

SECURITY TIP: Add a space before the command to prevent it from being
saved in your shell history. For example:
    seedify ~/.ssh/id_ed25519
    ^ (note the leading space)
Most shells (bash, zsh) are configured to ignore commands that start
with a space. Check your HISTCONTROL or HIST_IGNORE_SPACE settings.`,
		Example: `  seedify ~/.ssh/id_ed25519
  seedify ~/.ssh/id_ed25519 --words 12
  seedify ~/.ssh/id_ed25519 --words 12,24
  seedify ~/.ssh/id_ed25519 --words 12 --nostr
  seedify ~/.ssh/id_ed25519 --words 12,24 --nostr
  seedify ~/.ssh/id_ed25519 --nostr
  seedify ~/.ssh/id_ed25519 --words 12 --brain-bunker "my-passphrase"
  seedify ~/.ssh/id_ed25519 --btc --bip39-passphrase "my-wallet-passphrase"
  seedify ~/.ssh/id_ed25519 --eth --bip39-passphrase "my-wallet-passphrase"
  seedify ~/.ssh/id_ed25519 --brave
  seedify ~/.ssh/id_ed25519 --full
  seedify ~/.ssh/id_ed25519 --polyseed-year 2024
  seedify ~/.ssh/id_ed25519 --polyseed-year 2024 --polyseed-month 6
  seedify ~/.ssh/id_ed25519 --xmr --polyseed-year 2025
  seedify ~/.ssh/id_ed25519 --xmr --xmr-seed-offset "my-offset" --polyseed-year 2025
  seedify ~/.ssh/id_ed25519 --xmr --polyseed-year 2025 --polyseed-month 3
  cat ~/.ssh/id_ed25519 | seedify --words 18
  seedify ~/.ssh/id_ed25519 --to-rsa --output ~/.ssh/id_rsa_derived
  seedify ~/.ssh/id_ed25519 --to-rsa --reuse-passphrase --output ~/.ssh/id_rsa_derived
  seedify ~/.ssh/id_ed25519 --to-rsa --openssl-compatible --output ~/.ssh/id_rsa_derived.pem
  seedify ~/.ssh/id_ed25519 --to-dkim --output /etc/opendkim/keys/mail.private
  seedify ~/.ssh/id_ed25519 --to-dkim --dkim-selector mail --dkim-domain example.com --output /etc/opendkim/keys/mail.private
  seedify deployment-ssh-key --to-dkim --dkim-domain mail1.npub.cx --dkim-selector mail2026
  seedify ~/.ssh/id_ed25519 --to-dnssec --dnssec-domain example.com --dnssec-ksk --output ./dnssec-keys
  seedify ~/.ssh/id_ed25519 --to-jks --bits 2048 --jks-alias zenten --jks-validity 10000 --output zenten-release.jks`,
		Version:      fmt.Sprintf("%s (commit %s, built %s)", version, commit, date),
		Args:         cobra.MaximumNArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			// If no arguments provided and stdin is not a pipe, show help
			if len(args) == 0 {
				if fi, _ := os.Stdin.Stat(); (fi.Mode() & os.ModeNamedPipe) == 0 {
					return cmd.Help()
				}
			}

			if err := configureCLIOutput(cmd.Flags().Changed("config")); err != nil {
				return err
			}

			if err := setLanguage(language); err != nil {
				return err
			}

			var keyPath string
			if len(args) > 0 {
				keyPath = args[0]
			}

			// --openssl-compatible is only meaningful alongside --to-rsa.
			if deriveKeyPKCS8 && !deriveKeyToRSA {
				return errors.New("--openssl-compatible requires --to-rsa")
			}

			// --reuse-passphrase only applies to commands that prompt for a
			// fresh output passphrase: --to-rsa, --to-pgp, and --to-jks.
			if deriveKeyReusePassphrase && !deriveKeyToRSA && !deriveKeyToPGP && !deriveKeyToJKS {
				return errors.New("--reuse-passphrase requires --to-rsa, --to-pgp, or --to-jks")
			}

			// Key derivation modes are mutually exclusive.
			deriveModeCount := 0
			for _, enabled := range []bool{deriveKeyToRSA, deriveKeyToDKIM, deriveKeyToDNSSEC, deriveKeyToPGP, deriveKeyToJKS, deriveKeyToOnion, deriveKeyToI2P, deriveKeyToWireGuard} {
				if enabled {
					deriveModeCount++
				}
			}
			if deriveModeCount > 1 {
				return errors.New("key derivation flags are mutually exclusive")
			}

			if deriveKeyToDNSSEC {
				if deriveKeyDNSSECDomain == "" {
					return errors.New("--dnssec-domain is required with --to-dnssec")
				}
				if deriveKeyDNSSECKSK && deriveKeyDNSSECZSK {
					return errors.New("--dnssec-ksk and --dnssec-zsk are mutually exclusive")
				}
			}

			// --pgp-name and --pgp-email are both required when --to-pgp is set.
			if deriveKeyToPGP && deriveKeyPGPName == "" {
				return errors.New("--pgp-name is required with --to-pgp")
			}
			if deriveKeyToPGP && deriveKeyPGPEmail == "" {
				return errors.New("--pgp-email is required with --to-pgp")
			}

			if deriveKeyToJKS {
				if deriveKeyJKSAlias == "" {
					return errors.New("--jks-alias is required with --to-jks")
				}
				if deriveKeyOutput == "" {
					return errors.New("--output is required with --to-jks")
				}
				if deriveKeyJKSValidity < 1 {
					return errors.New("--jks-validity must be at least 1")
				}
			}

			// Handle --to-onion: derive a Tor v3 hidden service identity from the Ed25519 key.
			if deriveKeyToOnion {
				return runDeriveOnionKey(keyPath)
			}

			// Handle --to-i2p: derive an I2P Destination from the Ed25519 key.
			if deriveKeyToI2P {
				return runDeriveI2PKey(keyPath)
			}

			// Handle --to-wireguard: derive a WireGuard keypair from the Ed25519 key.
			if deriveKeyToWireGuard {
				return runDeriveWireGuardKey(keyPath)
			}

			// Handle --to-rsa: derive an RSA key from the Ed25519 key and write to disk (or stdout).
			if deriveKeyToRSA {
				return runDeriveKey(keyPath)
			}

			// Handle --to-dkim: derive a DKIM RSA keypair and write private key to disk (or stdout).
			if deriveKeyToDKIM {
				return runDeriveDKIMKey(keyPath)
			}

			// Handle --to-dnssec: derive a DNSSEC RSA keypair and write BIND-compatible files.
			if deriveKeyToDNSSEC {
				return runDeriveDNSSECKey(keyPath)
			}

			// Handle --to-pgp: derive an OpenPGP RSA keypair and write an ASCII-armored .asc file.
			if deriveKeyToPGP {
				return runDerivePGPKey(keyPath)
			}

			// Handle --to-jks: derive an RSA keypair and self-signed certificate as a JKS keystore.
			if deriveKeyToJKS {
				return runDeriveJKSKey(keyPath)
			}

			if brainBunkerKDFRounds < 1 {
				return errors.New("--brain-bunker-kdf-rounds must be at least 1")
			}
			if brainBunkerKDFRounds != defaultOpenSSHBcryptKDFRounds && seedPassphrase == "" {
				return errors.New("--brain-bunker-kdf-rounds requires --brain-bunker")
			}
			if brainBunkerKeyPassphrase != "" && seedPassphrase == "" {
				return errors.New("--brain-bunker-key-passphrase requires --brain-bunker")
			}

			// --xmr-seed-offset only applies to Monero address derivation.
			if xmrSeedOffset != "" && !monero && !moneroLegacy && !full {
				return errors.New("--xmr-seed-offset requires --xmr, --xmr-legacy, or --full")
			}

			// --publish requires --zentenprofile
			if publishRelays != "" && !zentenprofile {
				return errors.New("--publish requires --zentenprofile")
			}

			// Handle --sshkey-qr: print only the encrypted OpenSSH private key and its QR code.
			if sshKeyQR {
				err := runSSHKeyQR(keyPath)
				if err != nil {
					if strings.Contains(err.Error(), "key is not password-protected") {
						return formatPasswordError(err)
					}
					return err
				}
				return nil
			}

			// Handle --brave flag: generate 25-word phrase with Brave Sync
			// This is a special case that bypasses the unified output
			if brave {
				mnemonic, err := generateBraveSyncPhrase(keyPath, seedPassphrase)
				if err != nil {
					if strings.Contains(err.Error(), "key is not password-protected") {
						return formatPasswordError(err)
					}
					return err
				}

				fmt.Println(mnemonic)
				return nil
			}

			// Handle --zentenprofile flag: output public keys and addresses as DNS JSON.
			// This is a special case that bypasses the unified output.
			if zentenprofile {
				record, nostrKeys, err := generateDNSRecord(keyPath, seedPassphrase)
				if err != nil {
					if strings.Contains(err.Error(), "key is not password-protected") {
						return formatPasswordError(err)
					}
					return err
				}

				if publishRelays != "" {
					relays := parseRelayURLs(publishRelays)
					if len(relays) > 0 {
						if err := publishKind0CryptoTagsToRelays(record, nostrKeys, relays, blockchains); err != nil {
							return err
						}
					}
				}

				jsonBytes, err := json.MarshalIndent(record, "", "  ")
				if err != nil {
					return fmt.Errorf("failed to marshal DNS JSON: %w", err)
				}
				fmt.Println(string(jsonBytes))
				return nil
			}

			// Default: print curated seed phrases; with btc/eth/nostr/sol/tron/xmr flags,
			// also show the relevant portions of the full output for those chains.
			// When --words is specified, output only the requested word counts (no derivations).
			if !full {
				hasDerivationFlags := bitcoin || ethereum || zcash || nostr || solana || tron || monero || moneroLegacy || beldex || polyseedAll
				hasWordsFlag := wordCountStr != ""

				if hasWordsFlag {
					// --words specified: output only the requested seed phrases, no derivations
					parsedCounts, err := parseWordCounts(wordCountStr)
					if err != nil {
						return fmt.Errorf("invalid word counts: %w", err)
					}
					err = generateUnifiedOutput(keyPath, parsedCounts, seedPassphrase, xmrSeedOffset,
						false, false, false, false, false, false, false, false, false, false, false)
					if err != nil {
						if strings.Contains(err.Error(), "key is not password-protected") {
							return formatPasswordError(err)
						}
						return err
					}
				} else if hasDerivationFlags {
					wc := buildWordCounts(bitcoin, ethereum, zcash, solana, tron, nostr, monero, polyseedAll)
					err := generateUnifiedOutput(keyPath, wc, seedPassphrase, xmrSeedOffset,
						nostr, false, bitcoin, ethereum, zcash, solana, tron, monero, moneroLegacy, beldex, false)
					if err != nil {
						if strings.Contains(err.Error(), "key is not password-protected") {
							return formatPasswordError(err)
						}
						return err
					}
				} else {
					err := generatePhrasesOutput(keyPath, seedPassphrase)
					if err != nil {
						if strings.Contains(err.Error(), "key is not password-protected") {
							return formatPasswordError(err)
						}
						return err
					}
				}
				return nil
			}

			// --full: generate unified output (seed phrases + wallet derivations)
			hasWordsFlag := wordCountStr != ""
			hasNostrFlag := nostr
			hasCryptoFlags := bitcoin || ethereum || zcash || solana || tron || monero || moneroLegacy || beldex || polyseedAll || zentenprofile
			hasAnyDerivationFlags := hasWordsFlag || hasNostrFlag || hasCryptoFlags

			var wordCounts []int
			var deriveNostr bool
			var showBrave bool
			var deriveBtc, deriveEth, deriveZec, deriveSol, deriveTron, deriveXmr, deriveXmrLegacy, deriveBdx bool

			if !hasAnyDerivationFlags {
				wordCounts = []int{16, 24}
				deriveNostr = true
				showBrave = true
				deriveBtc = true
				deriveEth = true
				deriveZec = true
				deriveSol = true
				deriveTron = true
				deriveXmr = true
				deriveXmrLegacy = true
				deriveBdx = true
			} else {
				if hasWordsFlag {
					parsedCounts, err := parseWordCounts(wordCountStr)
					if err != nil {
						return fmt.Errorf("invalid word counts: %w", err)
					}
					wordCounts = parsedCounts
				} else if hasNostrFlag || hasCryptoFlags {
					wordCounts = buildWordCounts(bitcoin, ethereum, zcash, solana, tron, nostr, monero, polyseedAll)
				}
				deriveNostr = hasNostrFlag
				showBrave = false
				deriveBtc = bitcoin
				deriveEth = ethereum
				deriveZec = zcash
				deriveSol = solana
				deriveTron = tron
				deriveXmr = monero
				deriveXmrLegacy = moneroLegacy
				deriveBdx = beldex
			}

			uErr := generateUnifiedOutput(keyPath, wordCounts, seedPassphrase, xmrSeedOffset, deriveNostr, showBrave, deriveBtc, deriveEth, deriveZec, deriveSol, deriveTron, deriveXmr, deriveXmrLegacy, deriveBdx, true)
			if uErr != nil && strings.Contains(uErr.Error(), "key is not password-protected") {
				return formatPasswordError(uErr)
			}
			return uErr
		},
	}

	manCmd = &cobra.Command{
		Use:          "man",
		Args:         cobra.NoArgs,
		Short:        "generate man pages",
		Hidden:       true,
		SilenceUsage: true,
		RunE: func(*cobra.Command, []string) error {
			manPage, err := mcobra.NewManPage(1, rootCmd)
			if err != nil {
				//nolint: wrapcheck
				return err
			}
			manPage = manPage.WithSection("Copyright", "(C) 2022 Charmbracelet, Inc.\n"+
				"Released under MIT license.")
			fmt.Println(manPage.Build(roff.NewDocument()))
			return nil
		},
	}

	braveSync25thCmd = &cobra.Command{
		Use:   "brave-sync-25th",
		Short: "Get the 25th word for Brave Sync (changes daily)",
		Long: `Get the 25th word for Brave Sync based on the current date.

The 25th word changes daily and is calculated from the epoch date
"Tue, 10 May 2022 00:00:00 GMT". The number of days since the epoch
is used as an index into the BIP39 English word list.

This replicates the logic from:
https://alexeybarabash.github.io/25th-brave-sync-word/

Warning: Brave does not officially support using the Sync code as a backup
and you should not rely on this continuing to work in the future. Use the
export functionality in bookmarks and the password manager instead.`,
		Example: `  seedify brave-sync-25th
  seedify brave-sync-25th --date "2024-01-15"`,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(_ *cobra.Command, _ []string) error {
			var word string
			var err error

			// Check if a specific date was provided
			if dateStr != "" {
				date, parseErr := time.Parse("2006-01-02", dateStr)
				if parseErr != nil {
					return fmt.Errorf("could not parse date %q: use format YYYY-MM-DD: %w", dateStr, parseErr)
				}
				word, err = seedify.BraveSync25thWordForDate(date)
			} else {
				word, err = seedify.BraveSync25thWord()
			}

			if err != nil {
				return fmt.Errorf("could not get 25th word: %w", err)
			}

			fmt.Println(word)
			return nil
		},
	}

	dateStr string

	// completionCmd generates shell completion scripts for bash, zsh, fish, and powershell.
	completionCmd = &cobra.Command{
		Use:   "completion [bash|zsh|fish|powershell]",
		Short: "Generate shell completion script",
		Long: `Generate shell completion script for seedify.

To load completions:

Bash:
  $ source <(seedify completion bash)

  # To load completions for each session, execute once:
  # Linux:
  $ seedify completion bash > /etc/bash_completion.d/seedify
  # macOS:
  $ seedify completion bash > $(brew --prefix)/etc/bash_completion.d/seedify

Zsh:
  # If shell completion is not already enabled in your environment,
  # you will need to enable it. You can execute the following once:
  $ echo "autoload -U compinit; compinit" >> ~/.zshrc

  # To load completions for each session, execute once:
  $ seedify completion zsh > "${fpath[1]}/_seedify"

  # You will need to start a new shell for this setup to take effect.

Fish:
  $ seedify completion fish | source

  # To load completions for each session, execute once:
  $ seedify completion fish > ~/.config/fish/completions/seedify.fish

PowerShell:
  PS> seedify completion powershell | Out-String | Invoke-Expression

  # To load completions for every new session, run:
  PS> seedify completion powershell > seedify.ps1
  # and source this file from your PowerShell profile.
`,
		DisableFlagsInUseLine: true,
		ValidArgs:             []string{"bash", "zsh", "fish", "powershell"},
		Args:                  cobra.MatchAll(cobra.ExactArgs(1), cobra.OnlyValidArgs),
		SilenceUsage:          true,
		RunE: func(_ *cobra.Command, args []string) error {
			switch args[0] {
			case "bash":
				return rootCmd.GenBashCompletion(os.Stdout)
			case "zsh":
				return rootCmd.GenZshCompletion(os.Stdout)
			case "fish":
				return rootCmd.GenFishCompletion(os.Stdout, true)
			case "powershell":
				return rootCmd.GenPowerShellCompletionWithDesc(os.Stdout)
			default:
				return fmt.Errorf("unknown shell: %s", args[0])
			}
		},
	}
)

func init() {
	rootCmd.PersistentFlags().StringVarP(&language, "language", "l", "en", "Language")
	rootCmd.PersistentFlags().StringVarP(&wordCountStr, "words", "w", "", "Word counts to generate (comma-separated: 12,15,18,21,24)")
	rootCmd.PersistentFlags().StringVar(&seedPassphrase, "brain-bunker", "", "Derive and use an ephemeral SSH key from this secret for all seed/address output")
	rootCmd.PersistentFlags().IntVar(&brainBunkerKDFRounds, "brain-bunker-kdf-rounds", defaultOpenSSHBcryptKDFRounds, "bcrypt KDF rounds for encrypting the ephemeral SSH private key generated by --brain-bunker")
	rootCmd.PersistentFlags().StringVar(&brainBunkerKeyPassphrase, "brain-bunker-key-passphrase", "", "Protect the ephemeral SSH private key generated by --brain-bunker with this passphrase instead of the source SSH key passphrase")
	rootCmd.PersistentFlags().StringVar(&bip39Passphrase, "bip39-passphrase", "", "Optional BIP39 extension passphrase (25th word) when deriving wallet addresses from mnemonics; not the same as --brain-bunker")
	rootCmd.PersistentFlags().StringVar(&configPath, "config", "~/.seedify.ini", "INI config file for color overrides")
	rootCmd.PersistentFlags().BoolVar(&brave, "brave", false, "Generate 25-word phrase with Brave Sync")
	rootCmd.PersistentFlags().BoolVar(&full, "full", false, "Print full output (default word counts, Nostr keys, crypto derivations)")
	rootCmd.PersistentFlags().BoolVar(&nostr, "nostr", false, "Derive Nostr keys (npub/nsec) from seed phrase.")
	rootCmd.PersistentFlags().BoolVar(&bitcoin, "btc", false, "Derive Bitcoin address from 24-word seed phrase")
	rootCmd.PersistentFlags().BoolVar(&ethereum, "eth", false, "Derive Ethereum address from 24-word seed phrase")
	rootCmd.PersistentFlags().BoolVar(&zcash, "zec", false, "Derive Zcash address from 24-word seed phrase")
	rootCmd.PersistentFlags().BoolVar(&solana, "sol", false, "Derive Solana address from 24-word seed phrase")
	rootCmd.PersistentFlags().BoolVar(&tron, "tron", false, "Derive Tron address from 24-word seed phrase")
	rootCmd.PersistentFlags().BoolVar(&monero, "xmr", false, "Derive Monero address from 16-word polyseed")
	rootCmd.PersistentFlags().BoolVar(&moneroLegacy, "xmr-legacy", false, "Derive Monero address from 25-word legacy seed (shown alongside --xmr polyseed output)")
	rootCmd.PersistentFlags().StringVar(&xmrSeedOffset, "xmr-seed-offset", "", "Feather-compatible Monero seed offset passphrase for --xmr/--xmr-legacy address derivation")
	rootCmd.PersistentFlags().BoolVar(&beldex, "bdx", false, "Derive Beldex (BDX) address from 25-word legacy seed (same seed format as --xmr-legacy)")
	rootCmd.PersistentFlags().BoolVar(&sshKeyQR, "sshkey-qr", false, "Print the encrypted OpenSSH private key and display it as a terminal QR code")
	rootCmd.PersistentFlags().BoolVar(&zentenprofile, "zentenprofile", false, "Output public keys and addresses as DNS JSON to stdout")
	rootCmd.PersistentFlags().StringVar(&publishRelays, "publish", "", "When used with --zentenprofile: publish/update Nostr Kind 0 metadata crypto address tags to these relays (comma-separated, e.g. relay.primal.net,relay.damus.io)")
	rootCmd.PersistentFlags().StringVar(&blockchains, "blockchains", "", "When used with --zentenprofile --publish: comma-separated crypto labels to publish as Kind 0 tags. Default: all labels")
	rootCmd.PersistentFlags().StringVar(&polyseedYear, "polyseed-year", "", "Override polyseed year (YYYY). Default: current year")
	rootCmd.PersistentFlags().StringVar(&polyseedMonth, "polyseed-month", "", "Override polyseed month (1-12). Default: 1 (January)")
	rootCmd.PersistentFlags().BoolVar(&polyseedAll, "all-polyseeds", false, "Generate every possible polyseed (Nov 2021 – current month), one per month with correct birthday")
	rootCmd.PersistentFlags().BoolVar(&deriveKeyToRSA, "to-rsa", false, "Derive an RSA key from the input Ed25519 key and write it to --output")
	rootCmd.PersistentFlags().BoolVar(&deriveKeyToDKIM, "to-dkim", false, "Derive a DKIM RSA keypair from the input Ed25519 key; when --dkim-domain is set, writes config/dkim/<domain>/<selector>.private and .public automatically")
	rootCmd.PersistentFlags().BoolVar(&deriveKeyToDNSSEC, "to-dnssec", false, "Derive a DNSSEC RSASHA256 keypair from the input Ed25519 key; use --dnssec-domain and --output <dir>")
	rootCmd.PersistentFlags().BoolVar(&deriveKeyToOnion, "to-onion", false, "Derive a Tor v3 hidden service identity from the input Ed25519 key; use --output <dir> to write the Tor key files")
	rootCmd.PersistentFlags().BoolVar(&deriveKeyToI2P, "to-i2p", false, "Derive an I2P Destination (Ed25519 signing + X25519 encryption) from the input Ed25519 key; use --output <dir> to write the keys.dat file")
	rootCmd.PersistentFlags().BoolVar(&deriveKeyToWireGuard, "to-wireguard", false, "Derive a WireGuard static keypair from the input Ed25519 key; prints private and public keys in base64 (wg format)")
	rootCmd.PersistentFlags().BoolVar(&deriveKeyPKCS8, "openssl-compatible", false, "Write an encrypted PKCS#8 PEM file instead of OpenSSH format (used with --to-rsa; compatible with openssl pkey -check)")
	rootCmd.PersistentFlags().BoolVar(&deriveKeyToPGP, "to-pgp", false, "Derive an OpenPGP RSA keypair and write an ASCII-armored secret key (.asc) to --output")
	rootCmd.PersistentFlags().BoolVar(&deriveKeyToJKS, "to-jks", false, "Derive an RSA keypair and self-signed X.509 certificate as a Java KeyStore (.jks) to --output")
	rootCmd.PersistentFlags().StringVar(&deriveKeyPGPName, "pgp-name", "", "Full name for the OpenPGP UID, e.g. Alice (used with --to-pgp)")
	rootCmd.PersistentFlags().StringVar(&deriveKeyPGPEmail, "pgp-email", "", "Email address for the OpenPGP UID, e.g. alice@example.com (used with --to-pgp)")
	rootCmd.PersistentFlags().StringVar(&deriveKeyJKSAlias, "jks-alias", "", "Keystore entry alias, e.g. zenten (used with --to-jks)")
	rootCmd.PersistentFlags().IntVar(&deriveKeyJKSValidity, "jks-validity", seedify.DefaultJKSValidityDays, "Self-signed certificate validity in days (used with --to-jks)")
	rootCmd.PersistentFlags().StringVar(&deriveKeyJKSDN, "jks-dn", "", "Certificate distinguished name, e.g. CN=Zenten, OU=Mobile (used with --to-jks; default: CN=<jks-alias>)")
	rootCmd.PersistentFlags().StringVar(&deriveKeyOutput, "output", "", "Output file path for the derived key (used with --to-rsa, --to-dkim, --to-pgp, or --to-jks)")
	rootCmd.PersistentFlags().IntVar(&deriveKeyBits, "bits", 4096, "RSA key size in bits (2048, 3072, or 4096); used with --to-rsa, --to-dkim, --to-pgp, or --to-jks") //nolint:mnd
	rootCmd.PersistentFlags().StringVar(&deriveKeyDKIMSelector, "dkim-selector", "mail", "DKIM selector name for the DNS TXT record (used with --to-dkim)")
	rootCmd.PersistentFlags().StringVar(&deriveKeyDKIMDomain, "dkim-domain", "", "Domain for the DKIM DNS TXT record label, e.g. example.com (used with --to-dkim)")
	rootCmd.PersistentFlags().StringVar(&deriveKeyDNSSECDomain, "dnssec-domain", "", "Zone name for DNSSEC output, e.g. example.com (used with --to-dnssec)")
	rootCmd.PersistentFlags().IntVar(&deriveKeyDNSSECAlgorithm, "dnssec-algorithm", seedify.DNSSECAlgorithmRSASHA256, "DNSSEC algorithm number (8 = RSASHA256; used with --to-dnssec)")
	rootCmd.PersistentFlags().BoolVar(&deriveKeyDNSSECKSK, "dnssec-ksk", false, "Generate a DNSSEC KSK with flags 257 (default for --to-dnssec)")
	rootCmd.PersistentFlags().BoolVar(&deriveKeyDNSSECZSK, "dnssec-zsk", false, "Generate a DNSSEC ZSK with flags 256")
	rootCmd.PersistentFlags().BoolVar(&deriveKeyReusePassphrase, "reuse-passphrase", false, "Reuse the source key's passphrase to protect the derived key (used with --to-rsa, --to-pgp, or --to-jks); requires the source key to be password-protected")
	rootCmd.AddCommand(manCmd)
	rootCmd.AddCommand(braveSync25thCmd)
	rootCmd.AddCommand(completionCmd)
	braveSync25thCmd.Flags().StringVar(&dateStr, "date", "", "Get the 25th word for a specific date (format: YYYY-MM-DD)")
}

// getPolyseedYears returns the list of years to generate polyseeds for, based
// on the --polyseed-year flag. If the flag is empty, returns [lastYear, currentYear].
// If set, returns a single-element slice with the parsed year.
func getPolyseedYears() ([]int, error) {
	if polyseedYear == "" {
		return []int{time.Now().Year()}, nil
	}

	year, err := strconv.Atoi(polyseedYear)
	if err != nil {
		return nil, fmt.Errorf("expected a four-digit year (e.g. 2026), got %q", polyseedYear)
	}

	return []int{year}, nil
}

// getPolyseedMonth returns the calendar month to use for the polyseed birthday,
// based on the --polyseed-month flag. Returns time.January when the flag is not
// set, preserving the existing default behaviour. Returns an error if the value
// is present but is not a valid integer in the range 1–12.
func getPolyseedMonth() (time.Month, error) {
	if polyseedMonth == "" {
		return time.January, nil
	}

	m, err := strconv.Atoi(polyseedMonth)
	if err != nil {
		return time.January, fmt.Errorf("expected a month number 1–12 (e.g. 3 for March), got %q", polyseedMonth)
	}

	if m < 1 || m > 12 {
		return time.January, fmt.Errorf("month must be between 1 and 12, got %d", m)
	}

	return time.Month(m), nil //nolint:gosec
}

// birthdayFromYearMonth returns the Unix timestamp for the 1st day at 00:00 UTC
// of the given year and month, suitable for use as a polyseed birthday.
func birthdayFromYearMonth(year int, month time.Month) uint64 {
	return unixBirthday(time.Date(year, month, 1, 0, 0, 0, 0, time.UTC))
}

func birthdayFromDate(date time.Time) uint64 {
	year, month, day := date.UTC().Date()
	return unixBirthday(time.Date(year, month, day, 0, 0, 0, 0, time.UTC))
}

func polyseedPeriodBeginning(birthday uint64) time.Time {
	if birthday < polyseedBirthdayEpochUnix {
		birthday = polyseedBirthdayEpochUnix
	}
	period := (birthday - polyseedBirthdayEpochUnix) / polyseedBirthdayTimeStep
	startUnix := polyseedBirthdayEpochUnix + period*polyseedBirthdayTimeStep
	return time.Unix(int64(startUnix), 0).UTC() //nolint:gosec
}

func polyseedSlotLabel(slot yearMonth) string {
	periodStart := polyseedPeriodBeginning(birthdayFromYearMonth(slot.year, slot.month))
	return fmt.Sprintf("%d-%02d, period beginning %s", slot.year, int(slot.month), periodStart.Format("2006-01"))
}

func polyseedPEMLabel(slot yearMonth) string {
	return fmt.Sprintf("16-WORD POLYSEED (%s)", polyseedSlotLabel(slot))
}

func unixBirthday(date time.Time) uint64 {
	unix := date.Unix()
	if unix < 0 {
		return 0
	}
	return uint64(unix)
}

func zentenProfileRandomIndex(minIndex uint32, maxIndex uint32) (uint32, error) {
	if maxIndex < minIndex {
		return 0, fmt.Errorf("invalid random index range %d..%d", minIndex, maxIndex)
	}
	if maxIndex == minIndex {
		return minIndex, nil
	}

	span := uint64(maxIndex - minIndex + 1)
	n, err := rand.Int(rand.Reader, new(big.Int).SetUint64(span))
	if err != nil {
		return 0, fmt.Errorf("could not select random index: %w", err)
	}
	return minIndex + uint32(n.Uint64()), nil //nolint:gosec
}

type yearMonth struct {
	year  int
	month time.Month
}

// allPolyseedMonths returns every (year, month) pair from the Polyseed epoch
// (November 2021 — the library's base timestamp) through the current month,
// in chronological order. Each pair represents a unique wallet birthday.
func allPolyseedMonths() []yearMonth {
	// Polyseed epoch: 1 Nov 2021 (unix 1635768000)
	const epochYear, epochMonth = 2021, time.November
	now := time.Now().UTC()
	var out []yearMonth
	for y := epochYear; y <= now.Year(); y++ {
		startM := time.January
		if y == epochYear {
			startM = epochMonth
		}
		endM := time.December
		if y == now.Year() {
			endM = now.Month()
		}
		for m := startM; m <= endM; m++ {
			out = append(out, yearMonth{year: y, month: m})
		}
	}
	return out
}

// polyseedDayGroup holds a unique 16-word polyseed mnemonic together with the
// inclusive calendar-day range over which that mnemonic is produced.  Because
// the polyseed birthday has a resolution of ~30.44 days, consecutive days that
// fall within the same birthday step yield identical mnemonics and are merged
// into a single group.
type polyseedDayGroup struct {
	mnemonic   string
	legacySeed string
	startDate  time.Time
	endDate    time.Time
}

// groupPolyseedsByDay generates the 16-word polyseed for every calendar day
// from the Polyseed epoch (1 Nov 2021, 00:00 UTC) through today, groups
// consecutive days that produce an identical mnemonic, and returns the groups
// in chronological order.
func groupPolyseedsByDay(ed25519Key *ed25519.PrivateKey, seedPassphrase string) ([]polyseedDayGroup, error) {
	const epochYear, epochMonth, epochDay = 2021, time.November, 1
	now := time.Now().UTC()
	start := time.Date(epochYear, epochMonth, epochDay, 0, 0, 0, 0, time.UTC)

	var groups []polyseedDayGroup
	var prevMnemonic string

	for current := start; !current.After(now); current = current.AddDate(0, 0, 1) {
		birthday := uint64(current.Unix())                                                               //nolint:gosec
		mnemonic, mnErr := seedify.ToMnemonicWithLength(ed25519Key, 16, seedPassphrase, false, birthday) //nolint:mnd
		if mnErr != nil {
			return nil, fmt.Errorf("could not generate polyseed for %s: %w", current.Format("2006-01-02"), mnErr)
		}

		if mnemonic != prevMnemonic {
			legacySeed, lErr := seedify.ToMoneroLegacySeedFromPolyseed(mnemonic)
			if lErr != nil {
				return nil, fmt.Errorf("could not derive legacy seed for %s: %w", current.Format("2006-01-02"), lErr)
			}
			groups = append(groups, polyseedDayGroup{
				mnemonic:   mnemonic,
				legacySeed: legacySeed,
				startDate:  current,
				endDate:    current,
			})
			prevMnemonic = mnemonic
		} else {
			groups[len(groups)-1].endDate = current
		}
	}

	return groups, nil
}

// runDeriveKey is the handler for --to-rsa.
// It parses the source Ed25519 key, derives an RSA key, prompts for a
// passphrase, and writes the result as either:
//   - an OpenSSH PEM file (default, passphrase-protected via bcrypt-pbkdf), or
//   - an encrypted PKCS#8 PEM file when --openssl-compatible is set (PBES2/PBKDF2+AES-256-CBC,
//     readable by `openssl pkey -check` and `openssl rsa -check`).
//
//nolint:funlen,cyclop
func runDeriveKey(keyPath string) error {
	// Read and parse the source key.
	f, err := openFileOrStdin(keyPath)
	if err != nil {
		return fmt.Errorf("could not read key: %w", err)
	}
	defer f.Close() //nolint:errcheck

	bts, err := io.ReadAll(f)
	if err != nil {
		return fmt.Errorf("could not read key: %w", err)
	}

	var sourcePass []byte
	key, err := parsePrivateKey(bts, nil)
	if err != nil && isPasswordError(err) {
		sourcePass, err = askKeyPassphrase(keyPath)
		if err != nil {
			return err
		}
		key, err = parsePrivateKey(bts, sourcePass)
		if err != nil {
			return fmt.Errorf("could not parse key with passphrase: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("could not parse key: %w", err)
	}

	ed25519Key, ok := key.(*ed25519.PrivateKey)
	if !ok {
		return unsupportedKeyTypeError(key)
	}

	fmt.Fprintf(os.Stderr, "Deriving %d-bit RSA key (this may take a moment)...\n", deriveKeyBits)

	rsaKey, deriveErr := seedify.DeriveRSAKeyFromEd25519(ed25519Key, deriveKeyBits)
	if deriveErr != nil {
		return fmt.Errorf("could not derive RSA key: %w", deriveErr)
	}

	outputPass, err := readOutputPassphrase("derived key", sourcePass)
	if err != nil {
		return err
	}

	var pemBytes []byte

	if deriveKeyPKCS8 {
		// Serialise to encrypted PKCS#8 PEM using PBES2 (PBKDF2 + AES-256-CBC).
		// The resulting "BEGIN ENCRYPTED PRIVATE KEY" block is readable by
		// `openssl pkey -check` and `openssl rsa -check`.
		der, marshalErr := pkcs8.MarshalPrivateKey(rsaKey, outputPass, nil)
		if marshalErr != nil {
			return fmt.Errorf("could not marshal derived key to PKCS#8: %w", marshalErr)
		}
		pemBytes = pem.EncodeToMemory(&pem.Block{
			Type:  "ENCRYPTED PRIVATE KEY",
			Bytes: der,
		})
	} else {
		// Serialise to OpenSSH PEM format with passphrase protection
		// (bcrypt-pbkdf key derivation — the modern SSH default).
		pemBlock, marshalErr := ssh.MarshalPrivateKeyWithPassphrase(rsaKey, "", outputPass)
		if marshalErr != nil {
			return fmt.Errorf("could not marshal derived key: %w", marshalErr)
		}
		pemBytes = pem.EncodeToMemory(pemBlock)
	}

	// If no --output path was given, warn the user and ask for confirmation before
	// printing the private key to the console.
	if deriveKeyOutput == "" {
		confirmed, confirmErr := confirmPrintToConsole()
		if confirmErr != nil {
			return fmt.Errorf("could not read confirmation: %w", confirmErr)
		}
		if !confirmed {
			return errors.New("aborted: use --output <path> to write the derived key to a file")
		}

		fmt.Print(string(pemBytes))
		return nil
	}

	// Write the PEM file with restrictive permissions (owner read/write only).
	if err := os.WriteFile(deriveKeyOutput, pemBytes, 0o600); err != nil { //nolint:mnd
		return fmt.Errorf("could not write derived key to %s: %w", deriveKeyOutput, err)
	}

	fmt.Fprintf(os.Stderr, "Derived key written to: %s\n", deriveKeyOutput)

	return nil
}

// runDeriveDKIMKey handles --to-dkim: derives a DKIM RSA keypair from the source
// Ed25519 key, writes the PKCS#8 private key and the DNS TXT public key.
//
// Output path behaviour (in priority order):
//  1. --output <path>  – write private key to <path> (legacy, single-file mode;
//     public key / DNS record is printed to stderr as before).
//  2. --dkim-domain set, --output empty  – auto-derive paths:
//     config/dkim/<domain>/<selector>.private  (private key, 0600)
//     config/dkim/<domain>/<selector>.public   (DNS TXT record value, 0644)
//     The directory is created automatically.
//  3. Neither flag set – fall back to the stdout confirmation prompt.
//
// Unlike --to-rsa, the private key is written without a passphrase. DKIM private
// keys are conventionally stored unencrypted and protected only by filesystem
// permissions; mail server daemons (OpenDKIM, rspamd, Postfix milter) read them
// at startup without any interactive passphrase prompt.
//
//nolint:funlen,cyclop
func runDeriveDKIMKey(keyPath string) error {
	// Read and parse the source key.
	f, err := openFileOrStdin(keyPath)
	if err != nil {
		return fmt.Errorf("could not read key: %w", err)
	}
	defer f.Close() //nolint:errcheck

	bts, err := io.ReadAll(f)
	if err != nil {
		return fmt.Errorf("could not read key: %w", err)
	}

	key, err := parsePrivateKey(bts, nil)
	if err != nil && isPasswordError(err) {
		pass, passErr := askKeyPassphrase(keyPath)
		if passErr != nil {
			return passErr
		}
		key, err = parsePrivateKey(bts, pass)
		if err != nil {
			return fmt.Errorf("could not parse key with passphrase: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("could not parse key: %w", err)
	}

	ed25519Key, ok := key.(*ed25519.PrivateKey)
	if !ok {
		return unsupportedKeyTypeError(key)
	}

	fmt.Fprintf(os.Stderr, "Deriving %d-bit RSA keypair for DKIM (this may take a moment)...\n", deriveKeyBits)

	dkimKeys, deriveErr := seedify.DeriveDKIMKeypair(ed25519Key, deriveKeyDKIMSelector, deriveKeyBits)
	if deriveErr != nil {
		return fmt.Errorf("could not derive DKIM keypair: %w", deriveErr)
	}

	// Write or print the private key (no passphrase — DKIM convention).
	selector := deriveKeyDKIMSelector
	domain := deriveKeyDKIMDomain

	switch {
	case deriveKeyOutput == "" && domain != "":
		// Auto-derive mode: write both files under config/dkim/<domain>/
		dkimDir := filepath.Join("config", "dkim", domain)
		if mkdirErr := os.MkdirAll(dkimDir, 0o700); mkdirErr != nil { //nolint:mnd
			return fmt.Errorf("could not create DKIM directory %s: %w", dkimDir, mkdirErr)
		}

		privPath := filepath.Join(dkimDir, selector+".private")
		pubPath := filepath.Join(dkimDir, selector+".public")

		if writeErr := os.WriteFile(privPath, dkimKeys.PrivateKeyPEM, 0o600); writeErr != nil { //nolint:mnd
			return fmt.Errorf("could not write DKIM private key to %s: %w", privPath, writeErr)
		}
		pubContent := []byte(dkimKeys.DNSTXTRecord + "\n")
		if writeErr := os.WriteFile(pubPath, pubContent, 0o644); writeErr != nil { //nolint:gosec,mnd // DNS TXT record is public
			return fmt.Errorf("could not write DKIM public key to %s: %w", pubPath, writeErr)
		}

		fmt.Fprintf(os.Stderr, "DKIM private key written to: %s\n", privPath)
		fmt.Fprintf(os.Stderr, "DKIM public key written to:  %s\n", pubPath)

	case deriveKeyOutput != "":
		// Legacy explicit --output mode: write private key only.
		if writeErr := os.WriteFile(deriveKeyOutput, dkimKeys.PrivateKeyPEM, 0o600); writeErr != nil { //nolint:mnd
			return fmt.Errorf("could not write DKIM private key to %s: %w", deriveKeyOutput, writeErr)
		}

		fmt.Fprintf(os.Stderr, "DKIM private key written to: %s\n", deriveKeyOutput)

	default:
		// No --output and no --dkim-domain: fall back to stdout with confirmation.
		confirmed, confirmErr := confirmPrintToConsole()
		if confirmErr != nil {
			return fmt.Errorf("could not read confirmation: %w", confirmErr)
		}
		if !confirmed {
			return errors.New("aborted: use --output <path> or --dkim-domain <domain> to write the DKIM private key to a file")
		}

		fmt.Print(string(dkimKeys.PrivateKeyPEM))
	}

	// Print DNS TXT record instructions to stderr so only the private key
	// appears on stdout when the user pipes the output.
	// (Skipped in auto-derive mode since paths are already reported above.)
	if deriveKeyOutput != "" || domain == "" {
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "DNS TXT record for DKIM:")

		if domain != "" {
			fmt.Fprintf(os.Stderr, "  Name:  %s._domainkey.%s\n", selector, domain)
		} else {
			fmt.Fprintf(os.Stderr, "  Name:  %s._domainkey.<your-domain>\n", selector)
		}

		fmt.Fprintf(os.Stderr, "  Value: %s\n", dkimKeys.DNSTXTRecord)
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "Note: some DNS providers require TXT record values to be split into")
		fmt.Fprintln(os.Stderr, "      255-character chunks. Check your provider's documentation if")
		fmt.Fprintln(os.Stderr, "      the record is rejected. For a 4096-bit key the value is ~736")
		fmt.Fprintln(os.Stderr, "      characters; for 2048-bit it is ~392 characters.")
	} else {
		// Auto-derive mode: still show DNS record name and note for convenience.
		fmt.Fprintln(os.Stderr)
		fmt.Fprintf(os.Stderr, "DNS TXT record name: %s._domainkey.%s\n", selector, domain)
		fmt.Fprintf(os.Stderr, "DNS TXT record value is in: %s\n", filepath.Join("config", "dkim", domain, selector+".public"))
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "Note: some DNS providers require TXT record values to be split into")
		fmt.Fprintln(os.Stderr, "      255-character chunks. Check your provider's documentation if")
		fmt.Fprintln(os.Stderr, "      the record is rejected. For a 4096-bit key the value is ~736")
		fmt.Fprintln(os.Stderr, "      characters; for 2048-bit it is ~392 characters.")
	}

	return nil
}

// runDeriveDNSSECKey handles --to-dnssec: derives a DNSSEC RSA keypair from
// the source Ed25519 key and writes BIND-compatible .key/.private files plus a
// .ds helper file when --output <dir> is set. Without --output it prints the
// public DNSKEY and DS records only; private key material is not printed.
func runDeriveDNSSECKey(keyPath string) error {
	f, err := openFileOrStdin(keyPath)
	if err != nil {
		return fmt.Errorf("could not read key: %w", err)
	}
	defer f.Close() //nolint:errcheck

	bts, err := io.ReadAll(f)
	if err != nil {
		return fmt.Errorf("could not read key: %w", err)
	}

	key, err := parsePrivateKey(bts, nil)
	if err != nil && isPasswordError(err) {
		pass, passErr := askKeyPassphrase(keyPath)
		if passErr != nil {
			return passErr
		}
		key, err = parsePrivateKey(bts, pass)
		if err != nil {
			return fmt.Errorf("could not parse key with passphrase: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("could not parse key: %w", err)
	}

	ed25519Key, ok := key.(*ed25519.PrivateKey)
	if !ok {
		return unsupportedKeyTypeError(key)
	}

	flags := 257
	if deriveKeyDNSSECZSK {
		flags = 256
	}

	fmt.Fprintf(os.Stderr, "Deriving %d-bit DNSSEC RSASHA256 keypair for %s (this may take a moment)...\n", deriveKeyBits, deriveKeyDNSSECDomain)

	dnssecKeys, deriveErr := seedify.DeriveDNSSECKeypair(ed25519Key, deriveKeyDNSSECDomain, deriveKeyDNSSECAlgorithm, flags, deriveKeyBits)
	if deriveErr != nil {
		return fmt.Errorf("could not derive DNSSEC keypair: %w", deriveErr)
	}

	if deriveKeyOutput != "" {
		if mkdirErr := os.MkdirAll(deriveKeyOutput, 0o700); mkdirErr != nil { //nolint:mnd
			return fmt.Errorf("could not create DNSSEC output directory %s: %w", deriveKeyOutput, mkdirErr)
		}

		keyPathOut := filepath.Join(deriveKeyOutput, dnssecKeys.FileBase+".key")
		privatePathOut := filepath.Join(deriveKeyOutput, dnssecKeys.FileBase+".private")
		dsPathOut := filepath.Join(deriveKeyOutput, dnssecKeys.FileBase+".ds")

		if writeErr := os.WriteFile(keyPathOut, dnssecKeys.KeyFile, 0o644); writeErr != nil { //nolint:gosec,mnd // DNSKEY is public
			return fmt.Errorf("could not write DNSSEC public key to %s: %w", keyPathOut, writeErr)
		}
		if writeErr := os.WriteFile(privatePathOut, dnssecKeys.PrivateKeyFile, 0o600); writeErr != nil { //nolint:mnd
			return fmt.Errorf("could not write DNSSEC private key to %s: %w", privatePathOut, writeErr)
		}
		if writeErr := os.WriteFile(dsPathOut, []byte(dnssecKeys.DSRecord+"\n"), 0o644); writeErr != nil { //nolint:gosec,mnd // DS is public
			return fmt.Errorf("could not write DNSSEC DS record to %s: %w", dsPathOut, writeErr)
		}

		fmt.Fprintf(os.Stderr, "DNSSEC public key written to:  %s\n", keyPathOut)
		fmt.Fprintf(os.Stderr, "DNSSEC private key written to: %s\n", privatePathOut)
		fmt.Fprintf(os.Stderr, "DNSSEC DS record written to:   %s\n", dsPathOut)
		fmt.Fprintln(os.Stderr)
	}

	fmt.Fprintln(os.Stderr, "DNSSEC records:")
	fmt.Fprintf(os.Stderr, "  DNSKEY: %s\n", dnssecKeys.DNSKEYRecord)
	fmt.Fprintf(os.Stderr, "  DS:     %s\n", dnssecKeys.DSRecord)
	fmt.Fprintf(os.Stderr, "  Key ID: %05d\n", dnssecKeys.KeyTag)

	if deriveKeyOutput == "" {
		if _, printErr := fmt.Fprintln(os.Stdout, dnssecKeys.DNSKEYRecord); printErr != nil {
			return fmt.Errorf("could not print DNSKEY record: %w", printErr)
		}
		if _, printErr := fmt.Fprintln(os.Stdout, dnssecKeys.DSRecord); printErr != nil {
			return fmt.Errorf("could not print DS record: %w", printErr)
		}
	}

	return nil
}

// runDeriveOnionKey handles --to-onion: derives a Tor v3 hidden service identity
// from the source Ed25519 key and either writes the three Tor key files to a
// directory (when --output <dir> is given) or prints only the .onion address to
// stdout.
//
// The three files written when --output is set are:
//   - <dir>/hs_ed25519_secret_key  (96 bytes, permissions 0600)
//   - <dir>/hs_ed25519_public_key  (64 bytes, permissions 0600)
//   - <dir>/hostname               (the .onion address + newline)
//
// These match the layout Tor expects for a HiddenServiceDir; copy the
// directory to your Tor data path and add the corresponding HiddenServiceDir
// line to your torrc.
func runDeriveOnionKey(keyPath string) error {
	f, err := openFileOrStdin(keyPath)
	if err != nil {
		return fmt.Errorf("could not read key: %w", err)
	}
	defer f.Close() //nolint:errcheck

	bts, err := io.ReadAll(f)
	if err != nil {
		return fmt.Errorf("could not read key: %w", err)
	}

	key, err := parsePrivateKey(bts, nil)
	if err != nil && isPasswordError(err) {
		pass, passErr := askKeyPassphrase(keyPath)
		if passErr != nil {
			return passErr
		}
		key, err = parsePrivateKey(bts, pass)
		if err != nil {
			return fmt.Errorf("could not parse key with passphrase: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("could not parse key: %w", err)
	}

	ed25519Key, ok := key.(*ed25519.PrivateKey)
	if !ok {
		return unsupportedKeyTypeError(key)
	}

	onionKeys, deriveErr := seedify.DeriveOnionServiceKeys(ed25519Key)
	if deriveErr != nil {
		return fmt.Errorf("could not derive Tor v3 hidden service keys: %w", deriveErr)
	}

	// When no --output directory is given, just print the .onion address.
	if deriveKeyOutput == "" {
		fmt.Println(onionKeys.OnionAddress)
		return nil
	}

	// Create the output directory with restrictive permissions (owner only).
	if mkdirErr := os.MkdirAll(deriveKeyOutput, 0o700); mkdirErr != nil { //nolint:mnd
		return fmt.Errorf("could not create output directory %s: %w", deriveKeyOutput, mkdirErr)
	}

	secretKeyPath := filepath.Join(deriveKeyOutput, "hs_ed25519_secret_key")
	publicKeyPath := filepath.Join(deriveKeyOutput, "hs_ed25519_public_key")
	hostnamePath := filepath.Join(deriveKeyOutput, "hostname")

	if writeErr := os.WriteFile(secretKeyPath, onionKeys.PrivateKeyFile, 0o600); writeErr != nil { //nolint:mnd
		return fmt.Errorf("could not write %s: %w", secretKeyPath, writeErr)
	}
	if writeErr := os.WriteFile(publicKeyPath, onionKeys.PublicKeyFile, 0o600); writeErr != nil { //nolint:mnd
		return fmt.Errorf("could not write %s: %w", publicKeyPath, writeErr)
	}
	if writeErr := os.WriteFile(hostnamePath, onionKeys.HostnameFile, 0o644); writeErr != nil { //nolint:gosec,mnd // hostname file is the public .onion address, not a secret
		return fmt.Errorf("could not write %s: %w", hostnamePath, writeErr)
	}

	fmt.Fprintf(os.Stderr, "Onion address: %s\n", onionKeys.OnionAddress)
	fmt.Fprintf(os.Stderr, "Files written to: %s\n", deriveKeyOutput)
	fmt.Fprintf(os.Stderr, "  %s\n", secretKeyPath)
	fmt.Fprintf(os.Stderr, "  %s\n", publicKeyPath)
	fmt.Fprintf(os.Stderr, "  %s\n", hostnamePath)

	return nil
}

// runDeriveI2PKey handles --to-i2p: derives an I2P Destination (Ed25519 signing
// key + X25519 encryption key) from the source Ed25519 key and either writes
// the keys.dat file to a directory (when --output <dir> is given) or prints
// only the .b32.i2p address to stdout.
//
// When --output is set the following file is written:
//
//	<dir>/keys.dat  (391 + 64 bytes, permissions 0600)
//
// keys.dat is the private-key file format used by i2pd and Java I2P:
//
//	Destination bytes (public, 391 B) || X25519 private scalar (32 B) || Ed25519 seed (32 B)
//
// Point i2pd at the directory with:
//
//	[yourservice]
//	type = server
//	keys = keys.dat
func runDeriveI2PKey(keyPath string) error {
	f, err := openFileOrStdin(keyPath)
	if err != nil {
		return fmt.Errorf("could not read key: %w", err)
	}
	defer f.Close() //nolint:errcheck

	bts, err := io.ReadAll(f)
	if err != nil {
		return fmt.Errorf("could not read key: %w", err)
	}

	key, err := parsePrivateKey(bts, nil)
	if err != nil && isPasswordError(err) {
		pass, passErr := askKeyPassphrase(keyPath)
		if passErr != nil {
			return passErr
		}
		key, err = parsePrivateKey(bts, pass)
		if err != nil {
			return fmt.Errorf("could not parse key with passphrase: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("could not parse key: %w", err)
	}

	ed25519Key, ok := key.(*ed25519.PrivateKey)
	if !ok {
		return unsupportedKeyTypeError(key)
	}

	i2pKeys, deriveErr := seedify.DeriveI2PDestinationKeys(ed25519Key)
	if deriveErr != nil {
		return fmt.Errorf("could not derive I2P destination keys: %w", deriveErr)
	}

	// When no --output directory is given, print the address and private keys.
	if deriveKeyOutput == "" {
		fmt.Printf("B32 Address  : %s\n", i2pKeys.B32Address)
		fmt.Printf("X25519 PrivKey (hex): %x\n", i2pKeys.X25519PrivKey)
		fmt.Printf("Ed25519 Seed  (hex): %x\n", i2pKeys.Ed25519Seed)
		return nil
	}

	// Create the output directory with restrictive permissions (owner only).
	if mkdirErr := os.MkdirAll(deriveKeyOutput, 0o700); mkdirErr != nil { //nolint:mnd
		return fmt.Errorf("could not create output directory %s: %w", deriveKeyOutput, mkdirErr)
	}

	keysPath := filepath.Join(deriveKeyOutput, "keys.dat")

	if writeErr := os.WriteFile(keysPath, i2pKeys.PrivateKeyFile, 0o600); writeErr != nil { //nolint:mnd
		return fmt.Errorf("could not write %s: %w", keysPath, writeErr)
	}

	fmt.Fprintf(os.Stderr, "B32 address: %s\n", i2pKeys.B32Address)
	fmt.Fprintf(os.Stderr, "File written to: %s\n", keysPath)

	return nil
}

// runDeriveWireGuardKey handles --to-wireguard: derives a WireGuard static
// keypair from the source Ed25519 key and prints both keys in base64 (the
// format expected by wg(8)).
func runDeriveWireGuardKey(keyPath string) error {
	f, err := openFileOrStdin(keyPath)
	if err != nil {
		return fmt.Errorf("could not read key: %w", err)
	}
	defer f.Close() //nolint:errcheck

	bts, err := io.ReadAll(f)
	if err != nil {
		return fmt.Errorf("could not read key: %w", err)
	}

	key, err := parsePrivateKey(bts, nil)
	if err != nil && isPasswordError(err) {
		pass, passErr := askKeyPassphrase(keyPath)
		if passErr != nil {
			return passErr
		}
		key, err = parsePrivateKey(bts, pass)
		if err != nil {
			return fmt.Errorf("could not parse key with passphrase: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("could not parse key: %w", err)
	}

	ed25519Key, ok := key.(*ed25519.PrivateKey)
	if !ok {
		return unsupportedKeyTypeError(key)
	}

	wgKeys, deriveErr := seedify.DeriveWireGuardKeys(ed25519Key)
	if deriveErr != nil {
		return fmt.Errorf("could not derive WireGuard keys: %w", deriveErr)
	}

	fmt.Printf("PrivateKey = %s\n", wgKeys.PrivateKey)
	fmt.Printf("PublicKey  = %s\n", wgKeys.PublicKey)
	return nil
}

// runDerivePGPKey handles --to-pgp: derives a primary RSA signing key and an
// RSA encryption subkey from the source Ed25519 key, constructs a standard
// OpenPGP entity (v4), protects all private key material with the user's
// passphrase (S2K / AES-256-CFB), and writes an ASCII-armored secret key
// block to --output (or stdout after confirmation).
//
// The output is a "-----BEGIN PGP PRIVATE KEY BLOCK-----" file importable
// with `gpg --import`. After import GPG will show:
//
//	pub   rsa<bits> <date> [SC]
//	uid           <name> <email>
//	sub   rsa<bits> <date> [E]
//
// The creation timestamp is deterministic: it is derived from the primary
// key's domain hash so that the same source Ed25519 key always produces the
// same OpenPGP fingerprint regardless of when the command is run.
//
//nolint:funlen
func runDerivePGPKey(keyPath string) error {
	// Read and parse the source key.
	f, err := openFileOrStdin(keyPath)
	if err != nil {
		return fmt.Errorf("could not read key: %w", err)
	}
	defer f.Close() //nolint:errcheck

	bts, err := io.ReadAll(f)
	if err != nil {
		return fmt.Errorf("could not read key: %w", err)
	}

	var sourcePass []byte
	key, err := parsePrivateKey(bts, nil)
	if err != nil && isPasswordError(err) {
		sourcePass, err = askKeyPassphrase(keyPath)
		if err != nil {
			return err
		}
		key, err = parsePrivateKey(bts, sourcePass)
		if err != nil {
			return fmt.Errorf("could not parse key with passphrase: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("could not parse key: %w", err)
	}

	ed25519Key, ok := key.(*ed25519.PrivateKey)
	if !ok {
		return unsupportedKeyTypeError(key)
	}

	fmt.Fprintf(os.Stderr, "Deriving %d-bit RSA keypair for PGP (this may take a moment)...\n", deriveKeyBits)

	pgpPair, deriveErr := seedify.DerivePGPKeypair(ed25519Key, deriveKeyBits)
	if deriveErr != nil {
		return fmt.Errorf("could not derive PGP keypair: %w", deriveErr)
	}

	outputPass, err := readOutputPassphrase("PGP key", sourcePass)
	if err != nil {
		return err
	}

	// Build the primary key packet from the derived RSA key.
	primaryPrivPkt := packet.NewRSAPrivateKey(pgpPair.CreationTime, pgpPair.PrimaryKey)

	// Build the entity skeleton (no identities or subkeys yet).
	entity := &openpgp.Entity{
		PrimaryKey: &primaryPrivPkt.PublicKey,
		PrivateKey: primaryPrivPkt,
		Identities: make(map[string]*openpgp.Identity),
		Subkeys:    []openpgp.Subkey{},
		Signatures: []*packet.Signature{},
	}

	// Build the UID string ("Name <email>") and the positive-certification
	// self-signature that binds it to the primary key.
	uid := packet.NewUserId(deriveKeyPGPName, "", deriveKeyPGPEmail)
	if uid == nil {
		return errors.New("invalid PGP UID: name or email contains forbidden characters")
	}
	isPrimary := true
	uidSig := &packet.Signature{
		Version:           primaryPrivPkt.Version,
		SigType:           packet.SigTypePositiveCert,
		PubKeyAlgo:        primaryPrivPkt.PubKeyAlgo,
		Hash:              crypto.SHA256,
		CreationTime:      pgpPair.CreationTime,
		IssuerKeyId:       &primaryPrivPkt.KeyId,
		IssuerFingerprint: primaryPrivPkt.Fingerprint,
		FlagsValid:        true,
		FlagSign:          true,
		FlagCertify:       true,
		IsPrimaryId:       &isPrimary,
	}
	if uidErr := uidSig.SignUserId(uid.Id, &primaryPrivPkt.PublicKey, primaryPrivPkt, nil); uidErr != nil {
		return fmt.Errorf("could not self-sign PGP UID: %w", uidErr)
	}
	entity.Identities[uid.Id] = &openpgp.Identity{
		Name:          uid.Id,
		UserId:        uid,
		SelfSignature: uidSig,
		Signatures:    []*packet.Signature{uidSig},
	}

	// Build the encryption subkey packet from the second derived RSA key.
	encryptPrivPkt := packet.NewRSAPrivateKey(pgpPair.CreationTime, pgpPair.EncryptSubkey)
	encryptPrivPkt.IsSubkey = true

	subkeySig := &packet.Signature{
		Version:                   primaryPrivPkt.Version,
		SigType:                   packet.SigTypeSubkeyBinding,
		PubKeyAlgo:                primaryPrivPkt.PubKeyAlgo,
		Hash:                      crypto.SHA256,
		CreationTime:              pgpPair.CreationTime,
		IssuerKeyId:               &primaryPrivPkt.KeyId,
		IssuerFingerprint:         primaryPrivPkt.Fingerprint,
		FlagsValid:                true,
		FlagEncryptStorage:        true,
		FlagEncryptCommunications: true,
	}
	if subkeyErr := subkeySig.SignKey(&encryptPrivPkt.PublicKey, primaryPrivPkt, nil); subkeyErr != nil {
		return fmt.Errorf("could not bind PGP encryption subkey: %w", subkeyErr)
	}
	entity.Subkeys = append(entity.Subkeys, openpgp.Subkey{
		PublicKey:  &encryptPrivPkt.PublicKey,
		PrivateKey: encryptPrivPkt,
		Sig:        subkeySig,
	})

	// Encrypt all private key material with the user's passphrase before
	// serializing. We use SerializePrivateWithoutSigning afterwards to avoid
	// attempting to sign with the now-encrypted keys.
	if encErr := entity.EncryptPrivateKeys(outputPass, nil); encErr != nil {
		return fmt.Errorf("could not encrypt PGP private keys: %w", encErr)
	}

	// Serialize the entity into an ASCII-armored PGP PRIVATE KEY BLOCK.
	var buf bytes.Buffer
	armorWriter, armorErr := armor.Encode(&buf, openpgp.PrivateKeyType, nil)
	if armorErr != nil {
		return fmt.Errorf("could not create PGP armor writer: %w", armorErr)
	}
	if serErr := entity.SerializePrivateWithoutSigning(armorWriter, nil); serErr != nil {
		return fmt.Errorf("could not serialize PGP key: %w", serErr)
	}
	if closeErr := armorWriter.Close(); closeErr != nil {
		return fmt.Errorf("could not finalize PGP armor: %w", closeErr)
	}
	ascBytes := buf.Bytes()

	// Write to --output or print to stdout (with confirmation guard).
	if deriveKeyOutput == "" {
		confirmed, confirmErr := confirmPrintToConsole()
		if confirmErr != nil {
			return fmt.Errorf("could not read confirmation: %w", confirmErr)
		}
		if !confirmed {
			return errors.New("aborted: use --output <path> to write the PGP key to a file")
		}

		fmt.Print(string(ascBytes))
		return nil
	}

	if writeErr := os.WriteFile(deriveKeyOutput, ascBytes, 0o600); writeErr != nil { //nolint:mnd
		return fmt.Errorf("could not write PGP key to %s: %w", deriveKeyOutput, writeErr)
	}

	fmt.Fprintf(os.Stderr, "PGP key written to: %s\n", deriveKeyOutput)
	fmt.Fprintf(os.Stderr, "Import with: gpg --import %s\n", deriveKeyOutput)

	return nil
}

// runDeriveJKSKey handles --to-jks: derives an RSA keypair and self-signed
// X.509 certificate from the source Ed25519 key, then writes a password-protected
// Java KeyStore (.jks) file to --output.
//
//nolint:funlen,cyclop
func runDeriveJKSKey(keyPath string) error {
	f, err := openFileOrStdin(keyPath)
	if err != nil {
		return fmt.Errorf("could not read key: %w", err)
	}
	defer f.Close() //nolint:errcheck

	bts, err := io.ReadAll(f)
	if err != nil {
		return fmt.Errorf("could not read key: %w", err)
	}

	var sourcePass []byte
	key, err := parsePrivateKey(bts, nil)
	if err != nil && isPasswordError(err) {
		sourcePass, err = askKeyPassphrase(keyPath)
		if err != nil {
			return err
		}
		key, err = parsePrivateKey(bts, sourcePass)
		if err != nil {
			return fmt.Errorf("could not parse key with passphrase: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("could not parse key: %w", err)
	}

	ed25519Key, ok := key.(*ed25519.PrivateKey)
	if !ok {
		return unsupportedKeyTypeError(key)
	}

	var dn pkix.Name
	if deriveKeyJKSDN != "" {
		parsedDN, parseErr := seedify.ParseJKSDistinguishedName(deriveKeyJKSDN)
		if parseErr != nil {
			return fmt.Errorf("invalid --jks-dn: %w", parseErr)
		}
		dn = parsedDN
	}

	fmt.Fprintf(os.Stderr, "Deriving %d-bit RSA keypair for JKS alias %q (this may take a moment)...\n", deriveKeyBits, deriveKeyJKSAlias)

	jksPair, deriveErr := seedify.DeriveJKSKeypair(ed25519Key, deriveKeyJKSAlias, deriveKeyBits, deriveKeyJKSValidity, dn)
	if deriveErr != nil {
		return fmt.Errorf("could not derive JKS keypair: %w", deriveErr)
	}

	outputPass, err := readOutputPassphrase("JKS keystore", sourcePass)
	if err != nil {
		return err
	}

	jksBytes, err := seedify.EncodeJKS(jksPair, outputPass)
	if err != nil {
		return fmt.Errorf("could not encode JKS keystore: %w", err)
	}

	if writeErr := os.WriteFile(deriveKeyOutput, jksBytes, 0o600); writeErr != nil { //nolint:mnd
		return fmt.Errorf("could not write JKS keystore to %s: %w", deriveKeyOutput, writeErr)
	}

	jksBase64 := base64.StdEncoding.EncodeToString(jksBytes)
	storePassword := string(outputPass)

	fmt.Fprintf(os.Stderr, "JKS keystore written to: %s\n", deriveKeyOutput)
	fmt.Fprintf(os.Stderr, "Verify with: keytool -list -keystore %s -alias %s\n", deriveKeyOutput, deriveKeyJKSAlias)

	out.AndroidJKSSecretsSection(deriveKeyOutput, deriveKeyJKSAlias, storePassword, storePassword, jksBase64)

	return nil
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func openFileOrStdin(path string) (*os.File, error) {
	if path == "-" {
		return os.Stdin, nil
	}

	if fi, _ := os.Stdin.Stat(); (fi.Mode() & os.ModeNamedPipe) != 0 {
		return os.Stdin, nil
	}

	resolvedPath, err := expandPath(path)
	if err != nil {
		return nil, err
	}

	// G304: resolvedPath is user-provided input, which is expected for a CLI tool
	f, err := os.Open(resolvedPath) //nolint:gosec
	if err != nil {
		return nil, fmt.Errorf("could not open %s: %w", resolvedPath, err)
	}
	return f, nil
}

func parsePrivateKey(bts, pass []byte) (interface{}, error) {
	if len(pass) == 0 {
		//nolint: wrapcheck
		return ssh.ParseRawPrivateKey(bts)
	}
	//nolint: wrapcheck
	return ssh.ParseRawPrivateKeyWithPassphrase(bts, pass)
}

// runSSHKeyQR prints the encrypted OpenSSH private key bytes as a single
// unwrapped base64 line, followed by a terminal QR code containing the same raw
// one-line key text.
func runSSHKeyQR(path string) error {
	f, err := openFileOrStdin(path)
	if err != nil {
		return fmt.Errorf("could not read key: %w", err)
	}
	defer f.Close() //nolint:errcheck

	bts, err := io.ReadAll(f)
	if err != nil {
		return fmt.Errorf("could not read key: %w", err)
	}

	isProtected, err := isKeyPasswordProtected(bts)
	if err == nil && !isProtected {
		return fmt.Errorf("key is not password-protected: keys are required to be password-protected")
	}
	if err != nil {
		return err
	}

	keyLine, err := oneLinePrivateKeyRaw(bts)
	if err != nil {
		return err
	}

	fmt.Println(keyLine)
	fmt.Println()
	qrterminal.GenerateWithConfig(keyLine, qrterminal.Config{
		Level:      qrterminal.L,
		Writer:     os.Stdout,
		HalfBlocks: true,
		QuietZone:  2, //nolint:mnd // Compact terminal QR while retaining a scan-friendly border.
	})
	return nil
}

func oneLinePrivateKeyRaw(keyBytes []byte) (string, error) {
	block, _ := pem.Decode(keyBytes)
	if block == nil || block.Type != "OPENSSH PRIVATE KEY" {
		return "", errors.New("failed to decode OpenSSH private key PEM block")
	}

	return base64.StdEncoding.EncodeToString(block.Bytes), nil
}

// generateBraveSyncPhrase generates a 25-word seed phrase with Brave Sync.
// If seedPassphrase is set, it first activates the derived brain-bunker SSH key.
func generateBraveSyncPhrase(path string, seedPassphrase string) (string, error) {
	f, err := openFileOrStdin(path)
	if err != nil {
		return "", fmt.Errorf("could not read key: %w", err)
	}
	defer f.Close() //nolint:errcheck
	bts, err := io.ReadAll(f)
	if err != nil {
		return "", fmt.Errorf("could not read key: %w", err)
	}

	// Check if key is password-protected (required for this command)
	if isProtected, err := isKeyPasswordProtected(bts); err == nil && !isProtected {
		return "", fmt.Errorf("key is not password-protected: keys are required to be password-protected")
	}

	var sourcePass []byte
	key, err := parsePrivateKey(bts, nil)
	if err != nil && isPasswordError(err) {
		// Key requires a password - ask for it and parse again with the same bytes
		sourcePass, err = askKeyPassphrase(path)
		if err != nil {
			return "", err
		}
		// Parse again with the password using the bytes we already have
		key, err = parsePrivateKey(bts, sourcePass)
		if err != nil {
			return "", fmt.Errorf("could not parse key with passphrase: %w", err)
		}
	} else if err != nil {
		return "", fmt.Errorf("could not parse key: %w", err)
	}

	ed25519Key, ok := key.(*ed25519.PrivateKey)
	if !ok {
		return "", unsupportedKeyTypeError(key)
	}

	ed25519Key, _, err = activateBrainBunkerSSHKey(ed25519Key, bts, seedPassphrase, sourcePass, brainBunkerKeyPassphrase)
	if err != nil {
		return "", err
	}
	seedPassphrase = ""

	mnemonic, err := seedify.ToMnemonicWithBraveSync(ed25519Key, seedPassphrase)
	if err != nil {
		return "", fmt.Errorf("could not generate Brave Sync mnemonic: %w", err)
	}
	return mnemonic, nil
}

// printPEMPhrase prints a seed phrase wrapped in PEM-style BEGIN/END markers.
// The label is used in both the BEGIN and END lines (e.g., "12-WORD SEED PHRASE").
// Note: This function does not add extra spacing; callers are responsible for
// managing blank lines between outputs.
func printPEMPhrase(label string, phrase string) {
	out.PEMBlock(label, phrase, true)
}

func printMELTPhrase(phrase string) {
	out.PEMBlockDelimited("24-WORD SEED PHRASE (charmbracelet/MELT)", phrase, "=====", true)
}

// printSSHKeyPair prints the SSH public key (RFC 4716 OpenSSH PEM) with the
// key type prepended inside the block (ssh-ed25519 <base64> <npub>), the
// private key (OpenSSH PEM) with its SHA-256 hash, the raw 32-byte ed25519
// seed in hex with its SHA-256 hash, and the SHA-256 fingerprint of the public
// key. npub is appended as the authorized_keys-style comment on the public key
// line. privateKeyPEM must be OpenSSH PEM bytes for the key being printed.
func printSSHKeyPair(ed25519Key *ed25519.PrivateKey, privateKeyPEM []byte, npub string) error {
	sshPubKey, err := ssh.NewPublicKey(ed25519Key.Public())
	if err != nil {
		return fmt.Errorf("failed to encode SSH public key: %w", err)
	}

	pubB64 := base64.StdEncoding.EncodeToString(sshPubKey.Marshal())
	publicKeyLine := "ssh-ed25519 " + pubB64 + " " + npub
	out.PEMBlock("OPENSSH PUBLIC KEY", publicKeyLine, false)

	// pem.Decode extracts the raw OpenSSH key bytes so we can re-encode them
	// as a single unwrapped base64 line instead of the default 64-char wrapping.
	block, _ := pem.Decode(privateKeyPEM)
	if block == nil {
		return errors.New("failed to decode private key PEM block")
	}

	privB64 := base64.StdEncoding.EncodeToString(block.Bytes)
	out.PEMBlockPrefixed(1, "OPENSSH PRIVATE KEY", privB64, true)

	privHash := sha256.Sum256([]byte(privB64))
	out.PEMBlockPrefixed(1, "OPENSSH PRIVATE KEY HASH", hex.EncodeToString(privHash[:]), false)

	// Raw 32-byte seed — the root secret from which the key pair is derived.
	seedBytes := ed25519Key.Seed()
	seedHex := hex.EncodeToString(seedBytes)
	out.PEMBlockPrefixed(1, "ED25519 SEED", seedHex, true)

	seedHash := sha256.Sum256(seedBytes)
	out.PEMBlockPrefixed(1, "ED25519 SEED HASH", hex.EncodeToString(seedHash[:]), false)

	// SHA-256 fingerprint in the standard ssh-keygen format (SHA256:<base64>).
	sha256fp := ssh.FingerprintSHA256(sshPubKey)
	out.PEMBlockPrefixed(1, "OPENSSH FINGERPRINT", sha256fp, false)

	return nil
}

func printAllPolyseedPhrases(ed25519Key *ed25519.PrivateKey, seedPassphrase string) error {
	dayGroups16, err := groupPolyseedsByDay(ed25519Key, seedPassphrase)
	if err != nil {
		return err
	}
	for _, group := range dayGroups16 {
		label := fmt.Sprintf("16-WORD POLYSEED (%s → %s)",
			group.startDate.Format("2006-01-02"),
			group.endDate.Format("2006-01-02"),
		)
		fmt.Print("\n\n")
		printPEMPhrase(label, group.mnemonic)
	}
	return nil
}

func printMonthlyPolyseedPhrases(ed25519Key *ed25519.PrivateKey, seedPassphrase string) error {
	var slots16 []yearMonth
	years, err := getPolyseedYears()
	if err != nil {
		return fmt.Errorf("invalid --polyseed-year: %w", err)
	}
	month, err := getPolyseedMonth()
	if err != nil {
		return fmt.Errorf("invalid --polyseed-month: %w", err)
	}
	for _, year := range years {
		slots16 = append(slots16, yearMonth{year: year, month: month})
	}
	for _, slot := range slots16 {
		mnemonic16, mnErr := seedify.ToMnemonicWithLength(ed25519Key, 16, seedPassphrase, false, birthdayFromYearMonth(slot.year, slot.month)) //nolint:mnd
		if mnErr != nil {
			return fmt.Errorf("could not generate 16-word mnemonic for %d-%02d: %w", slot.year, int(slot.month), mnErr)
		}
		fmt.Print("\n\n")
		printPEMPhrase(polyseedPEMLabel(slot), mnemonic16)
	}
	return nil
}

func printPolyseedPhrases(ed25519Key *ed25519.PrivateKey, seedPassphrase string) error {
	if polyseedAll {
		return printAllPolyseedPhrases(ed25519Key, seedPassphrase)
	}
	return printMonthlyPolyseedPhrases(ed25519Key, seedPassphrase)
}

// generatePhrasesOutput generates a curated set of seed phrases from the SSH key.
// It prints the following phrases in order:
//  1. 16-word Polyseed seed phrase
//  2. 24-word BIP39 seed phrase
//  3. Nostr keys derived from the 24-word mnemonic (NIP-06 path)
//  4. Brave 25-word seed phrase (24 brave-prefixed words + 25th word)
//
//nolint:funlen
func generatePhrasesOutput(keyPath string, seedPassphrase string) error {
	// Parse the key once
	f, err := openFileOrStdin(keyPath)
	if err != nil {
		return fmt.Errorf("could not read key: %w", err)
	}
	defer f.Close() //nolint:errcheck
	bts, err := io.ReadAll(f)
	if err != nil {
		return fmt.Errorf("could not read key: %w", err)
	}

	// Check if key is password-protected (required)
	isProtected, err := isKeyPasswordProtected(bts)
	if err == nil && !isProtected {
		return fmt.Errorf("key is not password-protected: keys are required to be password-protected")
	}

	var sourcePass []byte
	key, err := parsePrivateKey(bts, nil)
	if err != nil && isPasswordError(err) {
		// Key requires a password - ask for it and parse again with the same bytes
		sourcePass, err = askKeyPassphrase(keyPath)
		if err != nil {
			return err
		}
		key, err = parsePrivateKey(bts, sourcePass)
		if err != nil {
			return fmt.Errorf("could not parse key with passphrase: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("could not parse key: %w", err)
	}

	ed25519Key, ok := key.(*ed25519.PrivateKey)
	if !ok {
		return unsupportedKeyTypeError(key)
	}

	privateKeyPEM := bts
	ed25519Key, privateKeyPEM, err = activateBrainBunkerSSHKey(ed25519Key, privateKeyPEM, seedPassphrase, sourcePass, brainBunkerKeyPassphrase)
	if err != nil {
		return err
	}
	seedPassphrase = ""

	// Pre-derive the 24-word mnemonic and Nostr keys so the npub can be used
	// as the public key comment before printing the SSH key pair.
	mnemonic24, err := seedify.ToMnemonicWithLength(ed25519Key, 24, seedPassphrase, false, 0) //nolint:mnd
	if err != nil {
		return fmt.Errorf("could not generate 24-word mnemonic: %w", err)
	}

	nostrKeys, err := seedify.DeriveNostrKeysWithHex(mnemonic24, bip39Passphrase)
	if err != nil {
		return fmt.Errorf("could not derive Nostr keys from 24-word mnemonic: %w", err)
	}

	out.SectionGap()
	if err := printSSHKeyPair(ed25519Key, privateKeyPEM, nostrKeys.Npub); err != nil {
		return err
	}

	// 1. 16-word seed phrases (Polyseed).
	// When --all-polyseeds is set, iterate every calendar day from the epoch
	// and emit one PEM block per unique mnemonic, labelled with its date range.
	// Otherwise emit one block per (year, month) slot as before.
	if err := printPolyseedPhrases(ed25519Key, seedPassphrase); err != nil {
		return err
	}

	// 2. 24-word seed phrase (standard, no prefix)
	// 2 empty lines between outputs
	out.SectionGap()
	printMELTPhrase(mnemonic24)

	// 3. Nostr keys derived from the 24-word mnemonic (NIP-06 path)
	out.SectionGap()
	out.NostrKeyBlock(nostrKeys.Npub, nostrKeys.PubKeyHex, nostrKeys.Nsec, nostrKeys.PrivKeyHex)

	// 4. Monero 25-word legacy seed (Electrum-style, "monero" prefix)
	moneroLegacySeed, err := seedify.ToMoneroLegacySeedWithPrefix(ed25519Key, seedPassphrase, "monero")
	if err != nil {
		return fmt.Errorf("could not generate Monero legacy seed: %w", err)
	}
	out.SectionGap()
	printPEMPhrase("25-WORD MONERO LEGACY SEED", moneroLegacySeed)

	// 5. Beldex 25-word seed ("beldex" prefix ensures divergence from Monero)
	bdxSeed, err := seedify.ToMoneroLegacySeedWithPrefix(ed25519Key, seedPassphrase, "beldex")
	if err != nil {
		return fmt.Errorf("could not generate Beldex seed: %w", err)
	}
	out.SectionGap()
	printPEMPhrase("25-WORD BELDEX (BDX) SEED", bdxSeed)

	// 6. Brave 25-word seed phrase (24 brave-prefixed words + 25th word)
	braveMnemonic, err := seedify.ToMnemonicWithBraveSync(ed25519Key, seedPassphrase)
	if err != nil {
		return fmt.Errorf("could not generate brave 25-word mnemonic: %w", err)
	}
	out.SectionGap()
	printPEMPhrase("25-WORD BRAVE-SYNC", braveMnemonic)

	// 2 empty lines after the last output
	out.SectionGap()

	return nil
}

func isPasswordError(err error) bool {
	var kerr *ssh.PassphraseMissingError
	return errors.As(err, &kerr)
}

// unsupportedKeyTypeError returns a consistent error for non-Ed25519 keys,
// directing users to --to-rsa if they have an RSA key.
func unsupportedKeyTypeError(key interface{}) error {
	msg := fmt.Sprintf("only Ed25519 SSH keys are supported for seed phrase derivation (got %T)", key)
	if _, ok := key.(*rsa.PrivateKey); ok {
		msg += "\n\nTo derive an RSA key from an Ed25519 key, use --to-rsa.\nTo use an RSA key for derivation, first convert it: seedify <ed25519-key> --to-rsa --output <path>"
	}
	return errors.New(msg)
}

// isKeyPasswordProtected checks if an SSH key requires a password.
// It attempts to parse the key without a password. If parsing succeeds,
// the key is not password-protected. If it fails with PassphraseMissingError,
// the key is password-protected.
func isKeyPasswordProtected(bts []byte) (bool, error) {
	_, err := parsePrivateKey(bts, nil)
	if err == nil {
		// Key parsed successfully without password - not password-protected
		return false, nil
	}
	if isPasswordError(err) {
		// Key requires a password - password-protected
		return true, nil
	}
	// Some other error occurred - we can't determine if it's password-protected
	// Return the error so the caller can handle it
	return false, fmt.Errorf("could not determine if key is password-protected: %w", err)
}

func getWidth(maxw int) int {
	w, _, err := term.GetSize(int(os.Stdout.Fd())) //nolint: gosec
	if err != nil || w > maxw {
		return maxWidth
	}
	return w
}

func renderBlock(w io.Writer, s lipgloss.Style, width int, str string) {
	_, _ = io.WriteString(w, s.Width(width).Render(str))
	_, _ = io.WriteString(w, "\n")
}

// formatPasswordError formats an error message with purple styling,
// similar to the success message format. It displays the styled error and returns
// a simple error so the command exits with a non-zero code.
func formatPasswordError(err error) error {
	if isatty.IsTerminal(os.Stdout.Fd()) {
		b := strings.Builder{}
		w := getWidth(maxWidth)

		b.WriteRune('\n')
		renderBlock(&b, errorStyle, w, err.Error())
		b.WriteRune('\n')

		fmt.Print(b.String())
	}
	// Return a simple error message (cobra may print this to stderr, but the styled
	// version has already been shown)
	return fmt.Errorf("keys are required to be password-protected")
}

// setLanguage sets the language of the big39 mnemonic seed.
func setLanguage(language string) error {
	list := getWordlist(language)
	if list == nil {
		return fmt.Errorf("this language is not supported")
	}
	bip39.SetWordList(list)
	return nil
}

func sanitizeLang(s string) string {
	return strings.ReplaceAll(strings.ToLower(s), " ", "-")
}

var wordLists = map[lang.Tag][]string{
	lang.Chinese:              wordlists.ChineseSimplified,
	lang.SimplifiedChinese:    wordlists.ChineseSimplified,
	lang.TraditionalChinese:   wordlists.ChineseTraditional,
	lang.Czech:                wordlists.Czech,
	lang.AmericanEnglish:      wordlists.English,
	lang.BritishEnglish:       wordlists.English,
	lang.English:              wordlists.English,
	lang.French:               wordlists.French,
	lang.Italian:              wordlists.Italian,
	lang.Japanese:             wordlists.Japanese,
	lang.Korean:               wordlists.Korean,
	lang.Spanish:              wordlists.Spanish,
	lang.EuropeanSpanish:      wordlists.Spanish,
	lang.LatinAmericanSpanish: wordlists.Spanish,
}

func getWordlist(language string) []string {
	language = sanitizeLang(language)
	tag := lang.Make(language)
	en := display.English.Languages() // default language name matcher
	for t := range wordLists {
		if sanitizeLang(en.Name(t)) == language {
			tag = t
			break
		}
	}
	if tag == lang.Und { // Unknown language
		return nil
	}
	base, _ := tag.Base()
	btag := lang.MustParse(base.String())
	wl := wordLists[tag]
	if wl == nil {
		return wordLists[btag]
	}
	return wl
}

func readPassword(msg string) ([]byte, error) {
	_, _ = fmt.Fprint(os.Stderr, msg)
	t, err := tty.Open()
	if err != nil {
		return nil, fmt.Errorf("could not open tty: %w", err)
	}
	defer t.Close()                                     //nolint: errcheck
	pass, err := term.ReadPassword(int(t.Input().Fd())) //nolint: gosec
	if err != nil {
		return nil, fmt.Errorf("could not read passphrase: %w", err)
	}
	return pass, nil
}

// generateUnifiedOutput generates seed phrases and wallet derivations for the specified word counts.
// It displays outputs in a fixed order: seed phrase first, then wallet derivations.
// When showPreamble is true, it first prints SSH key material, Tor onion address, and I2P destination;
// pass false for targeted invocations (chain flags, --words) that only need specific output.
// When deriveNostr is true, it derives Nostr keys directly from the SSH key (not from seed phrases).
// When showBrave is true, it also displays the brave 24-word seed phrase at the end.
// Crypto address flags (deriveBtc, deriveEth, deriveSol, deriveTron, deriveXmr) control which addresses to derive.
func generateUnifiedOutput(keyPath string, wordCounts []int, seedPassphrase string, xmrSeedOffset string, deriveNostr bool, showBrave bool, deriveBtc, deriveEth, deriveZec, deriveSol, deriveTron, deriveXmr, deriveXmrLegacy, deriveBdx bool, showPreamble bool) error {
	// Parse the key once
	f, err := openFileOrStdin(keyPath)
	if err != nil {
		return fmt.Errorf("could not read key: %w", err)
	}
	defer f.Close() //nolint:errcheck
	bts, err := io.ReadAll(f)
	if err != nil {
		return fmt.Errorf("could not read key: %w", err)
	}

	// Check if key is password-protected (required for this command)
	// If we can't determine protection status (err != nil), continue with normal parsing flow
	isProtected, err := isKeyPasswordProtected(bts)
	if err == nil && !isProtected {
		// Key is not password-protected - reject it
		return fmt.Errorf("key is not password-protected: keys are required to be password-protected")
	}

	var sourcePass []byte
	key, err := parsePrivateKey(bts, nil)
	if err != nil && isPasswordError(err) {
		// Key requires a password - ask for it and parse again with the same bytes
		sourcePass, err = askKeyPassphrase(keyPath)
		if err != nil {
			return err
		}
		// Parse again with the password using the bytes we already have
		key, err = parsePrivateKey(bts, sourcePass)
		if err != nil {
			return fmt.Errorf("could not parse key with passphrase: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("could not parse key: %w", err)
	}

	ed25519Key, ok := key.(*ed25519.PrivateKey)
	if !ok {
		return unsupportedKeyTypeError(key)
	}

	privateKeyPEM := bts
	ed25519Key, privateKeyPEM, err = activateBrainBunkerSSHKey(ed25519Key, privateKeyPEM, seedPassphrase, sourcePass, brainBunkerKeyPassphrase)
	if err != nil {
		return err
	}
	seedPassphrase = ""

	if showPreamble {
		if err := displayKeyPreamble(ed25519Key, privateKeyPEM, seedPassphrase); err != nil {
			return err
		}
	}

	// Resolve polyseed iteration list once before the word-count loop.
	// --all-polyseeds overrides --polyseed-year / --polyseed-month.
	var polyseedSlots []yearMonth
	if polyseedAll {
		polyseedSlots = allPolyseedMonths()
	} else {
		years, yErr := getPolyseedYears()
		if yErr != nil {
			return fmt.Errorf("invalid --polyseed-year: %w", yErr)
		}
		month, mErr := getPolyseedMonth()
		if mErr != nil {
			return fmt.Errorf("invalid --polyseed-month: %w", mErr)
		}
		for _, y := range years {
			polyseedSlots = append(polyseedSlots, yearMonth{year: y, month: month})
		}
	}

	// Generate and display outputs for each word count
	for i, count := range wordCounts {
		// For 16-word polyseed: when --all-polyseeds is set, iterate every
		// calendar day from the epoch and group consecutive days that produce
		// the same mnemonic, printing each unique mnemonic alongside its date
		// range.  Without --all-polyseeds, generate one mnemonic per
		// (year, month) slot as before.
		if count == 16 { //nolint:mnd,nestif
			if polyseedAll {
				dayGroups, dgErr := groupPolyseedsByDay(ed25519Key, seedPassphrase)
				if dgErr != nil {
					return dgErr
				}
				for _, g := range dayGroups {
					fmt.Printf("[16 word seed phrase (%s → %s)]\n",
						g.startDate.Format("2006-01-02"),
						g.endDate.Format("2006-01-02"),
					)
					fmt.Println()
					fmt.Println(g.mnemonic)
					fmt.Println(g.legacySeed)
					fmt.Println()

					if deriveXmr {
						xmrKeys, xmrErr := seedify.DeriveMoneroKeysWithSeedOffset(g.mnemonic, defaultXMRAddressCount, xmrSeedOffset)
						if xmrErr != nil {
							return fmt.Errorf("failed to derive Monero keys from 16-word polyseed (%s → %s): %w",
								g.startDate.Format("2006-01-02"), g.endDate.Format("2006-01-02"), xmrErr)
						}

						fmt.Printf("[%s (%s → %s)]\n",
							moneroAddressSectionTitle("monero addresses from 16 word polyseed", xmrSeedOffset),
							g.startDate.Format("2006-01-02"), g.endDate.Format("2006-01-02"))
						fmt.Println()
						fmt.Printf("%s (primary address)\n", xmrKeys.PrimaryAddress)
						for j, subaddr := range xmrKeys.Subaddresses {
							fmt.Printf("> %s (subaddress 0,%d)\n", subaddr, j+1)
						}
						fmt.Println()
					}

					if deriveXmr || deriveXmrLegacy {
						if err := displayMoneroLegacyOutput(ed25519Key, seedPassphrase, xmrSeedOffset); err != nil {
							return err
						}
					}
				}
			} else {
				for _, slot := range polyseedSlots {
					mnemonic, mnErr := seedify.ToMnemonicWithLength(ed25519Key, 16, seedPassphrase, false, birthdayFromYearMonth(slot.year, slot.month)) //nolint:mnd
					if mnErr != nil {
						return fmt.Errorf("could not generate 16-word mnemonic for %d-%02d: %w", slot.year, int(slot.month), mnErr)
					}

					out.Sectionf("16 word seed phrase (%s)", polyseedSlotLabel(slot))
					out.Blank()
					out.Sensitive(mnemonic)

					legacySeed, legacyErr := seedify.ToMoneroLegacySeedFromPolyseed(mnemonic)
					if legacyErr != nil {
						return fmt.Errorf("failed to derive Monero legacy seed from polyseed (%d-%02d): %w", slot.year, int(slot.month), legacyErr)
					}
					out.Sensitive(legacySeed)
					out.Blank()

					if deriveXmr {
						xmrKeys, xmrErr := seedify.DeriveMoneroKeysWithSeedOffset(mnemonic, defaultXMRAddressCount, xmrSeedOffset)
						if xmrErr != nil {
							return fmt.Errorf("failed to derive Monero keys from 16-word polyseed (%d-%02d): %w", slot.year, int(slot.month), xmrErr)
						}

						out.Sectionf("%s (%s)", moneroAddressSectionTitle("monero addresses from 16 word polyseed", xmrSeedOffset), polyseedSlotLabel(slot))
						out.Blank()
						out.Field(xmrKeys.PrimaryAddress, "primary address")
						for j, subaddr := range xmrKeys.Subaddresses {
							out.SubField(subaddr, fmt.Sprintf("subaddress 0,%d", j+1))
						}
						out.Blank()
					}

					if deriveXmr || deriveXmrLegacy {
						if err := displayMoneroLegacyOutput(ed25519Key, seedPassphrase, xmrSeedOffset); err != nil {
							return err
						}
					}
				}
			}
		} else {
			mnemonic, mnErr := seedify.ToMnemonicWithLength(ed25519Key, count, seedPassphrase, false, 0)
			if mnErr != nil {
				return fmt.Errorf("could not generate %d-word mnemonic: %w", count, mnErr)
			}

			out.Sectionf("%d word seed phrase", count)
			out.Blank()
			out.Sensitive(mnemonic)
			out.Blank()

			// Derive and display nostr keys for 12-word and 24-word seed phrases only
			if deriveNostr && (count == 12 || count == 24) {
				nostrKeys, nErr := seedify.DeriveNostrKeysWithHex(mnemonic, bip39Passphrase)
				if nErr != nil {
					return fmt.Errorf("failed to derive Nostr keys from %d-word mnemonic: %w", count, nErr)
				}

				out.Sectionf("nostr keys from %d word seed", count)
				out.Blank()
				out.Field(nostrKeys.Npub, `nostr public key aka "nostr user"`)
				out.TreeField(nostrKeys.PubKeyHex, "hex")
				out.SensitiveField(nostrKeys.Nsec, `nostr secret key aka "nostr pass"`)
				out.SensitiveTreeField(nostrKeys.PrivKeyHex, "hex")
				out.Blank()
			}

			// Derive and display Bitcoin keys for 12 or 24-word seed phrase
			if (count == 12 || count == 24) && deriveBtc {
				if btcErr := displayBitcoinOutput(mnemonic, count); btcErr != nil {
					return btcErr
				}
			}

			// Derive and display Ethereum/Solana/Tron and other chain addresses for 24-word seed phrase only.
			// Extra chains (Litecoin, Dogecoin, Cosmos, Noble, Sui, Stellar, Ripple) are only shown when
			// the user has requested at least one crypto derivation via --btc, --eth, --sol, or --tron.
			// This keeps --words 24 output minimal when no derivation flags are passed.
			if count == 24 { //nolint:mnd
				hasAnyCryptoFlag := deriveBtc || deriveEth || deriveZec || deriveSol || deriveTron

				// Ethereum address
				if deriveEth {
					ethAddr, ethErr := seedify.DeriveEthereumAddress(mnemonic, bip39Passphrase)
					if ethErr != nil {
						return fmt.Errorf("failed to derive Ethereum address from 24-word seed: %w", ethErr)
					}

					out.AddressSection("ethereum address from 24 word seed", ethAddr)
				}

				// Zcash address (below Ethereum, shown when any crypto derivation is requested)
				if hasAnyCryptoFlag {
					zcashAddr, zErr := seedify.DeriveZcashAddress(mnemonic, bip39Passphrase)
					if zErr != nil {
						return fmt.Errorf("failed to derive Zcash address from 24-word seed: %w", zErr)
					}

					out.AddressSection("zcash address from 24 word seed", zcashAddr)
				}

				// Solana address
				if deriveSol {
					solAddr, solErr := seedify.DeriveSolanaAddress(mnemonic, bip39Passphrase)
					if solErr != nil {
						return fmt.Errorf("failed to derive Solana address from 24-word seed: %w", solErr)
					}

					out.AddressSection("solana address from 24 word seed", solAddr)
				}

				// Tron address
				if deriveTron {
					tronAddr, tErr := seedify.DeriveTronAddress(mnemonic, bip39Passphrase)
					if tErr != nil {
						return fmt.Errorf("failed to derive Tron address from 24-word seed: %w", tErr)
					}

					out.AddressSection("tron address from 24 word seed", tronAddr)
				}

				// EVM-compatible chain addresses (reuse Ethereum address)
				if deriveEth {
					evmAddr, evmErr := seedify.DeriveEthereumAddress(mnemonic, bip39Passphrase)
					if evmErr != nil {
						return fmt.Errorf("failed to derive EVM address from 24-word seed: %w", evmErr)
					}

					out.AddressSection("arbitrum address from 24 word seed", evmAddr)
					out.AddressSection("avalanche address from 24 word seed", evmAddr)
					out.AddressSection("base address from 24 word seed", evmAddr)
					out.AddressSection("bnbchain address from 24 word seed", evmAddr)
					out.AddressSection("cronos address from 24 word seed", evmAddr)
					out.AddressSection("optimism address from 24 word seed", evmAddr)
					out.AddressSection("polygon address from 24 word seed", evmAddr)
				}

				// Extra chains: only show when user requested at least one crypto derivation
				if hasAnyCryptoFlag {
					// Litecoin address (native SegWit)
					ltcAddr, ltcErr := seedify.DeriveLitecoinAddress(mnemonic, bip39Passphrase)
					if ltcErr != nil {
						return fmt.Errorf("failed to derive Litecoin address from 24-word seed: %w", ltcErr)
					}

					out.AddressSection("litecoin address from 24 word seed", ltcAddr)

					// Dogecoin address
					dogeAddr, dogeErr := seedify.DeriveDogecoinAddress(mnemonic, bip39Passphrase)
					if dogeErr != nil {
						return fmt.Errorf("failed to derive Dogecoin address from 24-word seed: %w", dogeErr)
					}

					out.AddressSection("dogecoin address from 24 word seed", dogeAddr)

					// Cosmos address
					cosmosAddr, cosmosErr := seedify.DeriveCosmosAddress(mnemonic, bip39Passphrase)
					if cosmosErr != nil {
						return fmt.Errorf("failed to derive Cosmos address from 24-word seed: %w", cosmosErr)
					}

					out.AddressSection("cosmos address from 24 word seed", cosmosAddr)

					// Noble address
					nobleAddr, nobleErr := seedify.DeriveNobleAddress(mnemonic, bip39Passphrase)
					if nobleErr != nil {
						return fmt.Errorf("failed to derive Noble address from 24-word seed: %w", nobleErr)
					}

					out.AddressSection("noble address from 24 word seed", nobleAddr)

					// Sui address
					suiAddr, suiErr := seedify.DeriveSuiAddress(mnemonic, bip39Passphrase)
					if suiErr != nil {
						return fmt.Errorf("failed to derive Sui address from 24-word seed: %w", suiErr)
					}

					out.AddressSection("sui address from 24 word seed", suiAddr)

					// Stellar address
					xlmAddr, xlmErr := seedify.DeriveStellarAddress(mnemonic, bip39Passphrase)
					if xlmErr != nil {
						return fmt.Errorf("failed to derive Stellar address from 24-word seed: %w", xlmErr)
					}

					out.AddressSection("stellar address from 24 word seed", xlmAddr)

					// Ripple address
					xrpAddr, xrpErr := seedify.DeriveRippleAddress(mnemonic, bip39Passphrase)
					if xrpErr != nil {
						return fmt.Errorf("failed to derive Ripple address from 24-word seed: %w", xrpErr)
					}

					out.AddressSection("ripple address from 24 word seed", xrpAddr)
				}
			}
		}

		// Add blank line between word counts (except after the last one, unless brave is also shown)
		if i < len(wordCounts)-1 || showBrave {
			out.Blank()
		}
	}

	// Monero legacy uses a year-independent 25-word seed derived directly from the SSH key.
	// When the 16-word polyseed section ran, legacy output is already shown there.
	if deriveXmrLegacy && !wordCountsInclude(wordCounts, 16) { //nolint:mnd
		if err := displayMoneroLegacyOutput(ed25519Key, seedPassphrase, xmrSeedOffset); err != nil {
			return err
		}
	}

	if deriveBdx {
		if err := displayBeldexOutput(ed25519Key, seedPassphrase); err != nil {
			return err
		}
	}

	// Display brave 25-word seed phrase at the end if requested
	if showBrave {
		braveMnemonic, err := seedify.ToMnemonicWithBraveSync(ed25519Key, seedPassphrase)
		if err != nil {
			return fmt.Errorf("could not generate brave 25-word mnemonic: %w", err)
		}

		out.SeedSection("25 word brave seed phrase", braveMnemonic)
	}

	return nil
}

// parseWordCounts parses a comma-separated string of word counts and validates them.
// Valid word counts are: 12, 15, 16, 18, 21, or 24.
func parseWordCounts(wordCountStr string) ([]int, error) {
	if wordCountStr == "" {
		return []int{12, 15, 16, 18, 21, 24}, nil
	}

	validCounts := map[int]bool{12: true, 15: true, 16: true, 18: true, 21: true, 24: true}
	parts := strings.Split(wordCountStr, ",")
	wordCounts := make([]int, 0, len(parts))

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		count, err := strconv.Atoi(part)
		if err != nil {
			return nil, fmt.Errorf("invalid word count %q: %w", part, err)
		}

		if !validCounts[count] {
			return nil, fmt.Errorf("invalid word count: %d (must be 12, 15, 16, 18, 21, or 24)", count)
		}

		wordCounts = append(wordCounts, count)
	}

	if len(wordCounts) == 0 {
		return []int{12, 15, 16, 18, 21, 24}, nil
	}

	return wordCounts, nil
}

func wordCountsInclude(wordCounts []int, count int) bool {
	for _, wc := range wordCounts {
		if wc == count {
			return true
		}
	}
	return false
}

// buildWordCounts returns the ordered word-count slice for generateUnifiedOutput based on the active
// chain-derivation flags. It excludes 16 for --xmr-legacy and --bdx because those flags use
// year-independent 25-word legacy seeds that are printed by the dedicated helpers after the loop.
func buildWordCounts(bitcoin, ethereum, zcash, solana, tron, nostrFlag, monero, polyseedAll bool) []int {
	var wc []int
	if bitcoin {
		wc = append(wc, 12) //nolint:mnd
	}
	if monero || polyseedAll {
		wc = append(wc, 16) //nolint:mnd
	}
	if bitcoin || ethereum || zcash || solana || tron || nostrFlag {
		wc = append(wc, 24) //nolint:mnd
	}
	return wc
}

func askKeyPassphrase(path string) ([]byte, error) {
	defer fmt.Fprintf(os.Stderr, "\n")
	return readPassword(fmt.Sprintf("Enter the passphrase to unlock %q: ", path))
}

// readOutputPassphrase prompts the user for a passphrase to protect a derived
// key, asking for confirmation. When --reuse-passphrase is set and a non-empty
// sourcePass is available, it returns sourcePass directly without prompting.
// label is interpolated into prompts and error messages, e.g. "derived key" or
// "PGP key".
func readOutputPassphrase(label string, sourcePass []byte) ([]byte, error) {
	if deriveKeyReusePassphrase {
		if len(sourcePass) == 0 {
			return nil, errors.New("--reuse-passphrase requires the source key to be password-protected")
		}
		fmt.Fprintf(os.Stderr, "Reusing source key passphrase for the %s.\n", label)
		return sourcePass, nil
	}

	fmt.Fprintf(os.Stderr, "Enter a passphrase for the %s (cannot be empty): ", label)
	pass, err := readPassword("")
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, fmt.Errorf("could not read passphrase: %w", err)
	}
	if len(pass) == 0 {
		return nil, fmt.Errorf("passphrase for %s cannot be empty", label)
	}

	fmt.Fprintf(os.Stderr, "Confirm passphrase: ")
	confirm, err := readPassword("")
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, fmt.Errorf("could not read passphrase confirmation: %w", err)
	}
	if string(pass) != string(confirm) {
		return nil, errors.New("passphrases do not match")
	}
	return pass, nil
}

// confirmPrintToConsole warns the user that no --output path was provided and
// asks whether they want to print the derived private key to the console.
// It returns true only when the user explicitly presses 'y' or 'Y'.
func confirmPrintToConsole() (bool, error) {
	fmt.Fprintf(os.Stderr, "\nWARNING: No --output path provided. The derived private key will be printed to the console.\n")
	fmt.Fprintf(os.Stderr, "Print private key to console? [y/N]: ")

	t, err := tty.Open()
	if err != nil {
		return false, fmt.Errorf("could not open tty: %w", err)
	}
	defer t.Close() //nolint:errcheck

	r, err := t.ReadRune()
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return false, fmt.Errorf("could not read response: %w", err)
	}

	return r == 'y' || r == 'Y', nil
}

// displayBitcoinOutput displays all Bitcoin derivations for a given mnemonic.
// This includes addresses with private keys, extended keys, and multisig addresses.
//
//nolint:funlen
func displayBitcoinOutput(mnemonic string, wordCount int) error {
	// === MASTER EXTENDED KEYS ===
	// The master key is the root of the HD wallet tree (path: m)
	// This is the same key regardless of which BIP standard you're using

	masterExtended, err := seedify.DeriveBitcoinMasterExtendedKeys(mnemonic, bip39Passphrase)
	if err != nil {
		return fmt.Errorf("failed to derive Bitcoin master extended keys: %w", err)
	}

	out.Sectionf("bitcoin master extended keys from %d word seed", wordCount)
	out.Blank()
	out.Field(masterExtended.ExtendedPublicKey, "master xpub at m")
	out.SensitiveField(masterExtended.ExtendedPrivateKey, "master xprv at m")
	out.Blank()

	// === SINGLE-SIG ADDRESSES AND PRIVATE KEYS ===

	// Legacy P2PKH (BIP44)
	legacyKeys, err := seedify.DeriveBitcoinLegacyKeys(mnemonic, bip39Passphrase)
	if err != nil {
		return fmt.Errorf("failed to derive Bitcoin legacy keys: %w", err)
	}

	// SegWit P2SH-P2WPKH (BIP49)
	segwitKeys, err := seedify.DeriveBitcoinSegwitKeys(mnemonic, bip39Passphrase)
	if err != nil {
		return fmt.Errorf("failed to derive Bitcoin SegWit keys: %w", err)
	}

	// Native SegWit P2WPKH (BIP84)
	nativeKeys, err := seedify.DeriveBitcoinNativeSegwitKeys(mnemonic, bip39Passphrase)
	if err != nil {
		return fmt.Errorf("failed to derive Bitcoin native SegWit keys: %w", err)
	}

	out.Sectionf("bitcoin addresses from %d word seed", wordCount)
	out.Blank()
	out.Field(legacyKeys.Address, "legacy P2PKH - BIP44 m/44'/0'/0'/0/0")
	out.Field(segwitKeys.Address, "segwit P2SH-P2WPKH - BIP49 m/49'/0'/0'/0/0")
	out.Field(nativeKeys.Address, "native segwit P2WPKH - BIP84 m/84'/0'/0'/0/0")
	out.Blank()

	// === PRIVATE KEYS (WIF) ===

	out.Sectionf("bitcoin private keys from %d word seed", wordCount)
	out.Blank()
	out.SensitiveField(legacyKeys.PrivateWIF, "legacy P2PKH - BIP44")
	out.SensitiveField(segwitKeys.PrivateWIF, "segwit P2SH-P2WPKH - BIP49")
	out.SensitiveField(nativeKeys.PrivateWIF, "native segwit P2WPKH - BIP84")
	out.Blank()

	// === ACCOUNT-LEVEL EXTENDED KEYS ===
	// These are derived to the account level for each BIP standard
	// Import these into wallets to derive all addresses for that account

	// Legacy extended keys (xpub/xprv)
	legacyExtended, err := seedify.DeriveBitcoinLegacyExtendedKeys(mnemonic, bip39Passphrase)
	if err != nil {
		return fmt.Errorf("failed to derive Bitcoin legacy extended keys: %w", err)
	}

	// SegWit extended keys (ypub/yprv)
	segwitExtended, err := seedify.DeriveBitcoinSegwitExtendedKeys(mnemonic, bip39Passphrase)
	if err != nil {
		return fmt.Errorf("failed to derive Bitcoin SegWit extended keys: %w", err)
	}

	// Native SegWit extended keys (zpub/zprv)
	nativeExtended, err := seedify.DeriveBitcoinNativeSegwitExtendedKeys(mnemonic, bip39Passphrase)
	if err != nil {
		return fmt.Errorf("failed to derive Bitcoin native SegWit extended keys: %w", err)
	}

	out.Sectionf("bitcoin account extended public keys from %d word seed", wordCount)
	out.Blank()
	out.Field(legacyExtended.ExtendedPublicKey, "legacy account xpub - BIP44 m/44'/0'/0'")
	out.Field(segwitExtended.ExtendedPublicKey, "segwit account ypub - BIP49 m/49'/0'/0'")
	out.Field(nativeExtended.ExtendedPublicKey, "native segwit account zpub - BIP84 m/84'/0'/0'")
	out.Blank()

	out.Sectionf("bitcoin account extended private keys from %d word seed", wordCount)
	out.Blank()
	out.SensitiveField(legacyExtended.ExtendedPrivateKey, "legacy account xprv - BIP44 m/44'/0'/0'")
	out.SensitiveField(segwitExtended.ExtendedPrivateKey, "segwit account yprv - BIP49 m/49'/0'/0'")
	out.SensitiveField(nativeExtended.ExtendedPrivateKey, "native segwit account zprv - BIP84 m/84'/0'/0'")
	out.Blank()

	// === MULTISIG 1-OF-1 ADDRESSES AND PRIVATE KEYS ===

	// Legacy multisig P2SH (BIP48)
	multisigLegacyKeys, err := seedify.DeriveBitcoinMultisigLegacyKeys(mnemonic, bip39Passphrase)
	if err != nil {
		return fmt.Errorf("failed to derive Bitcoin multisig legacy keys: %w", err)
	}

	// SegWit multisig P2SH-P2WSH (BIP48)
	multisigSegwitKeys, err := seedify.DeriveBitcoinMultisigSegwitKeys(mnemonic, bip39Passphrase)
	if err != nil {
		return fmt.Errorf("failed to derive Bitcoin multisig SegWit keys: %w", err)
	}

	// Native SegWit multisig P2WSH (BIP48)
	multisigNativeKeys, err := seedify.DeriveBitcoinMultisigNativeSegwitKeys(mnemonic, bip39Passphrase)
	if err != nil {
		return fmt.Errorf("failed to derive Bitcoin multisig native SegWit keys: %w", err)
	}

	// === PAYNYM (BIP47) ===
	payNymKeys, err := seedify.DerivePayNym(mnemonic, bip39Passphrase)
	if err != nil {
		return fmt.Errorf("failed to derive PayNym: %w", err)
	}

	out.Sectionf("bitcoin PayNym (BIP47) from %d word seed", wordCount)
	out.Blank()
	out.Field(payNymKeys.PaymentCode, "payment code - BIP47 m/47'/0'/0'")
	out.Field(payNymKeys.NotificationAddress, "notification address - m/47'/0'/0'/0")
	out.Blank()

	out.Sectionf("bitcoin multisig 1-of-1 addresses from %d word seed", wordCount)
	out.Blank()
	out.Field(multisigLegacyKeys.Address, "legacy P2SH - BIP48 m/48'/0'/0'/0'/0/0")
	out.Field(multisigSegwitKeys.Address, "segwit P2SH-P2WSH - BIP48 m/48'/0'/0'/1'/0/0")
	out.Field(multisigNativeKeys.Address, "native segwit P2WSH - BIP48 m/48'/0'/0'/2'/0/0")
	out.Blank()

	out.Sectionf("bitcoin multisig 1-of-1 private keys from %d word seed", wordCount)
	out.Blank()
	out.SensitiveField(multisigLegacyKeys.PrivateWIF, "legacy P2SH - BIP48")
	out.SensitiveField(multisigSegwitKeys.PrivateWIF, "segwit P2SH-P2WSH - BIP48")
	out.SensitiveField(multisigNativeKeys.PrivateWIF, "native segwit P2WSH - BIP48")
	out.Blank()

	// === MULTISIG ACCOUNT-LEVEL EXTENDED KEYS ===

	// Legacy multisig extended keys (xpub/xprv)
	multisigLegacyExtended, err := seedify.DeriveBitcoinMultisigLegacyExtendedKeys(mnemonic, bip39Passphrase)
	if err != nil {
		return fmt.Errorf("failed to derive Bitcoin multisig legacy extended keys: %w", err)
	}

	// SegWit multisig extended keys (Ypub/Yprv)
	multisigSegwitExtended, err := seedify.DeriveBitcoinMultisigSegwitExtendedKeys(mnemonic, bip39Passphrase)
	if err != nil {
		return fmt.Errorf("failed to derive Bitcoin multisig SegWit extended keys: %w", err)
	}

	// Native SegWit multisig extended keys (Zpub/Zprv)
	multisigNativeExtended, err := seedify.DeriveBitcoinMultisigNativeSegwitExtendedKeys(mnemonic, bip39Passphrase)
	if err != nil {
		return fmt.Errorf("failed to derive Bitcoin multisig native SegWit extended keys: %w", err)
	}

	out.Sectionf("bitcoin multisig 1-of-1 account extended public keys from %d word seed", wordCount)
	out.Blank()
	out.Field(multisigLegacyExtended.ExtendedPublicKey, "legacy account xpub - BIP48 m/48'/0'/0'/0")
	out.Field(multisigSegwitExtended.ExtendedPublicKey, "segwit account Ypub - BIP48 m/48'/0'/0'/1")
	out.TreeField(multisigSegwitExtended.StandardPublicKey, "xpub")
	out.Field(multisigNativeExtended.ExtendedPublicKey, "native segwit account Zpub - BIP48 m/48'/0'/0'/2")
	out.TreeField(multisigNativeExtended.StandardPublicKey, "xpub")
	out.Blank()

	out.Sectionf("bitcoin multisig 1-of-1 account extended private keys from %d word seed", wordCount)
	out.Blank()
	out.SensitiveField(multisigLegacyExtended.ExtendedPrivateKey, "legacy account xprv - BIP48 m/48'/0'/0'/0")
	out.SensitiveField(multisigSegwitExtended.ExtendedPrivateKey, "segwit account Yprv - BIP48 m/48'/0'/0'/1")
	out.SensitiveTreeField(multisigSegwitExtended.StandardPrivateKey, "xprv")
	out.SensitiveField(multisigNativeExtended.ExtendedPrivateKey, "native segwit account Zprv - BIP48 m/48'/0'/0'/2")
	out.SensitiveTreeField(multisigNativeExtended.StandardPrivateKey, "xprv")
	out.Blank()

	return nil
}

// displayMoneroLegacyOutput derives and prints the 25-word Monero legacy (Electrum-style) seed and
// the primary address plus subaddresses derived from it. Used for --xmr-legacy without polyseed output.
func displayMoneroLegacyOutput(ed25519Key *ed25519.PrivateKey, seedPassphrase string, xmrSeedOffset string) error {
	legacySeed, legacyErr := seedify.ToMoneroLegacySeedWithPrefix(ed25519Key, seedPassphrase, "monero")
	if legacyErr != nil {
		return fmt.Errorf("failed to derive Monero legacy seed: %w", legacyErr)
	}

	out.SeedSection("25 word monero legacy seed", legacySeed)

	return displayMoneroLegacyAddresses(legacySeed, xmrSeedOffset)
}

// displayMoneroLegacyAddresses prints Monero primary and subaddresses from a 25-word legacy seed.
func displayMoneroLegacyAddresses(legacySeed string, xmrSeedOffset string) error {
	legacyKeys, legacyKErr := seedify.DeriveMoneroKeysFromLegacySeedWithSeedOffset(legacySeed, defaultXMRAddressCount, xmrSeedOffset)
	if legacyKErr != nil {
		return fmt.Errorf("failed to derive Monero keys from legacy seed: %w", legacyKErr)
	}

	out.Section(moneroAddressSectionTitle("monero addresses from 25 word legacy seed", xmrSeedOffset))
	out.Blank()
	out.Field(legacyKeys.PrimaryAddress, "primary address")
	for j, subaddr := range legacyKeys.Subaddresses {
		out.SubField(subaddr, fmt.Sprintf("subaddress 0,%d", j+1))
	}
	out.Blank()
	return nil
}

func moneroAddressSectionTitle(base string, xmrSeedOffset string) string {
	if xmrSeedOffset == "" {
		return base
	}
	return base + " with seed offset"
}

// displayKeyPreamble prints the SSH key pair, Tor onion address, and I2P destination before seed output.
func displayKeyPreamble(ed25519Key *ed25519.PrivateKey, privateKeyPEM []byte, seedPassphrase string) error {
	mnemonic24, m24Err := seedify.ToMnemonicWithLength(ed25519Key, 24, seedPassphrase, false, 0) //nolint:mnd
	if m24Err != nil {
		return fmt.Errorf("could not generate 24-word mnemonic for key comment: %w", m24Err)
	}
	nostrKeys, nkErr := seedify.DeriveNostrKeysWithHex(mnemonic24, bip39Passphrase)
	if nkErr != nil {
		return fmt.Errorf("could not derive Nostr keys for key comment: %w", nkErr)
	}

	out.SectionGap()
	if err := printSSHKeyPair(ed25519Key, privateKeyPEM, nostrKeys.Npub); err != nil {
		return err
	}

	onionKeys, onionErr := seedify.DeriveOnionServiceKeys(ed25519Key)
	if onionErr != nil {
		return fmt.Errorf("could not derive Tor v3 hidden service keys: %w", onionErr)
	}
	out.PEMBlockPrefixed(1, "TOR ONION ADDRESS", onionKeys.OnionAddress, false)

	i2pKeys, i2pErr := seedify.DeriveI2PDestinationKeys(ed25519Key)
	if i2pErr != nil {
		return fmt.Errorf("could not derive I2P destination keys: %w", i2pErr)
	}
	out.Blanks(1)
	out.LabeledBlock("I2P DESTINATION", []string{
		"B32 Address  : " + i2pKeys.B32Address,
		fmt.Sprintf("X25519 PrivKey (hex): %x", i2pKeys.X25519PrivKey),
		fmt.Sprintf("Ed25519 Seed  (hex): %x", i2pKeys.Ed25519Seed),
	})
	out.Blank()
	return nil
}

func activateBrainBunkerSSHKey(sourceKey *ed25519.PrivateKey, sourcePrivateKeyPEM []byte, brainBunker string, sourcePass []byte, overrideKeyPassphrase string) (*ed25519.PrivateKey, []byte, error) {
	if brainBunker == "" {
		return sourceKey, sourcePrivateKeyPEM, nil
	}

	keyPassphrase := sourcePass
	if overrideKeyPassphrase != "" {
		keyPassphrase = []byte(overrideKeyPassphrase)
	} else if len(keyPassphrase) == 0 {
		return nil, nil, errors.New("--brain-bunker requires the source key to be password-protected unless --brain-bunker-key-passphrase is set")
	}

	ephemeralKey := deriveBrainBunkerSSHKey(sourceKey, brainBunker)
	pemBlock, marshalErr := marshalOpenSSHEd25519PrivateKeyWithPassphraseKDFRounds(ephemeralKey, "", keyPassphrase, brainBunkerKDFRounds)
	if marshalErr != nil {
		return nil, nil, fmt.Errorf("could not encode brain-bunker SSH key: %w", marshalErr)
	}
	privateKeyPEM := pem.EncodeToMemory(pemBlock)
	if privateKeyPEM == nil {
		return nil, nil, errors.New("could not encode brain-bunker SSH key PEM")
	}
	return &ephemeralKey, privateKeyPEM, nil
}

func deriveBrainBunkerSSHKey(sourceKey *ed25519.PrivateKey, brainBunker string) ed25519.PrivateKey {
	bunkerHash := sha256.Sum256([]byte(brainBunker))
	seedMaterial := append(bunkerHash[:], sourceKey.Seed()...)
	derivedSeed := sha256.Sum256(seedMaterial)
	return ed25519.NewKeyFromSeed(derivedSeed[:])
}

// displayBeldexOutput derives and prints the 25-word Beldex seed (same Electrum encoding as Monero
// but with a "beldex" prefix for domain separation) and the primary address plus subaddresses.
func displayBeldexOutput(ed25519Key *ed25519.PrivateKey, seedPassphrase string) error {
	bdxSeed, bdxSeedErr := seedify.ToMoneroLegacySeedWithPrefix(ed25519Key, seedPassphrase, "beldex")
	if bdxSeedErr != nil {
		return fmt.Errorf("failed to derive Beldex seed: %w", bdxSeedErr)
	}

	out.SeedSection("25 word beldex (bdx) seed", bdxSeed)

	bdxKeys, bdxKErr := seedify.DeriveBeldexKeysFromLegacySeed(bdxSeed, 9) //nolint:mnd
	if bdxKErr != nil {
		return fmt.Errorf("failed to derive Beldex keys from legacy seed: %w", bdxKErr)
	}

	out.Section("beldex addresses from 25 word seed")
	out.Blank()
	out.Field(bdxKeys.PrimaryAddress, "primary address")
	for j, subaddr := range bdxKeys.Subaddresses {
		out.SubField(subaddr, fmt.Sprintf("subaddress 0,%d", j+1))
	}
	out.Blank()
	return nil
}

type zentenProfileEntry struct {
	TagName string
	Value   string
}

// dnsRecord represents the JSON structure for DNS output.
// Fields are ordered to match the expected DNS JSON format.
// Exactly one of SSHEd25519 or SSHRSA will be populated per record, depending
// on the input key type; the empty one is omitted from JSON output.
//
//nolint:govet
type dnsRecord struct {
	SSHEd25519    string `json:"ssh-ed25519,omitempty"`
	SSHRSA        string `json:"ssh-rsa,omitempty"`
	Nostr         string `json:"nostr"`
	Npub          string `json:"npub"`
	NpubKey       string `json:"npubkey"`
	PubKey        string `json:"pubkey"`
	HexPub        string `json:"hexpub"`
	HexPubKey     string `json:"hexpubkey"`
	Bitcoin       string `json:"bitcoin"`
	SilentPayment string `json:"silentpayment"`
	PayNym        string `json:"paynym"`
	Litecoin      string `json:"litecoin"`
	Dogecoin      string `json:"dogecoin"`
	Monero        string `json:"monero"`
	Cosmos        string `json:"cosmos"`
	Noble         string `json:"noble"`
	Arbitrum      string `json:"arbitrum"`
	Avalanche     string `json:"avalanche"`
	Base          string `json:"base"`
	BNBChain      string `json:"bnbchain"`
	Celo          string `json:"celo"`
	Cronos        string `json:"cronos"`
	Ethereum      string `json:"ethereum"`
	HyperEVM      string `json:"hyperevm"`
	Zcash         string `json:"zcash"`
	Optimism      string `json:"optimism"`
	Polygon       string `json:"polygon"`
	Solana        string `json:"solana"`
	Sui           string `json:"sui"`
	Tron          string `json:"tron"`
	Stellar       string `json:"stellar"`
	Ripple        string `json:"ripple"`
}

// tagsToNostrTags converts [][]string to nostrpkg.Tags ([]nostrpkg.Tag).
func tagsToNostrTags(tags [][]string) nostrpkg.Tags {
	out := make(nostrpkg.Tags, len(tags))
	for i, t := range tags {
		out[i] = nostrpkg.Tag(t)
	}
	return out
}

func parseBlockchainLabels(labels string) map[string]struct{} {
	if strings.TrimSpace(labels) == "" {
		return nil
	}

	parts := strings.Split(labels, ",")
	selected := make(map[string]struct{}, len(parts))
	for _, part := range parts {
		label := strings.ToLower(strings.TrimSpace(part))
		if label != "" {
			selected[label] = struct{}{}
		}
	}
	return selected
}

func zentenProfileCryptoEntries(record dnsRecord) []zentenProfileEntry {
	entries := make([]zentenProfileEntry, 0, 24) //nolint:mnd
	addEntry := func(name, value string) {
		if value != "" {
			entries = append(entries, zentenProfileEntry{TagName: name, Value: value})
		}
	}
	addEntry("bitcoin", record.Bitcoin)
	addEntry("silentpayment", record.SilentPayment)
	addEntry("paynym", record.PayNym)
	addEntry("litecoin", record.Litecoin)
	addEntry("dogecoin", record.Dogecoin)
	addEntry("monero", record.Monero)
	addEntry("cosmos", record.Cosmos)
	addEntry("noble", record.Noble)
	addEntry("arbitrum", record.Arbitrum)
	addEntry("avalanche", record.Avalanche)
	addEntry("base", record.Base)
	addEntry("bnbchain", record.BNBChain)
	addEntry("celo", record.Celo)
	addEntry("cronos", record.Cronos)
	addEntry("ethereum", record.Ethereum)
	addEntry("hyperevm", record.HyperEVM)
	addEntry("zcash", record.Zcash)
	addEntry("optimism", record.Optimism)
	addEntry("polygon", record.Polygon)
	addEntry("solana", record.Solana)
	addEntry("sui", record.Sui)
	addEntry("tron", record.Tron)
	addEntry("stellar", record.Stellar)
	addEntry("ripple", record.Ripple)
	return entries
}

func managedKind0CryptoTagNames() map[string]struct{} {
	managed := make(map[string]struct{}, 24) //nolint:mnd
	for _, entry := range zentenProfileCryptoEntries(dnsRecord{
		Bitcoin:       "x",
		SilentPayment: "x",
		PayNym:        "x",
		Litecoin:      "x",
		Dogecoin:      "x",
		Monero:        "x",
		Cosmos:        "x",
		Noble:         "x",
		Arbitrum:      "x",
		Avalanche:     "x",
		Base:          "x",
		BNBChain:      "x",
		Celo:          "x",
		Cronos:        "x",
		Ethereum:      "x",
		HyperEVM:      "x",
		Zcash:         "x",
		Optimism:      "x",
		Polygon:       "x",
		Solana:        "x",
		Sui:           "x",
		Tron:          "x",
		Stellar:       "x",
		Ripple:        "x",
	}) {
		managed[entry.TagName] = struct{}{}
	}
	return managed
}

func filteredKind0CryptoEntries(record dnsRecord, labels string) []zentenProfileEntry {
	entries := zentenProfileCryptoEntries(record)
	selected := parseBlockchainLabels(labels)
	if selected == nil {
		return entries
	}

	filtered := make([]zentenProfileEntry, 0, len(entries))
	for _, entry := range entries {
		if _, ok := selected[entry.TagName]; ok {
			filtered = append(filtered, entry)
		}
	}
	return filtered
}

func kind0CryptoTags(record dnsRecord, labels string) [][]string {
	entries := filteredKind0CryptoEntries(record, labels)
	tags := make([][]string, 0, len(entries))
	for _, entry := range entries {
		tags = append(tags, []string{entry.TagName, entry.Value})
	}
	return tags
}

func defaultKind0Content(nostrKeys *seedify.NostrKeys) (string, error) {
	name := nostrKeys.Npub
	if len(name) > 4 { //nolint:mnd
		name = name[len(name)-4:]
	}

	content := map[string]string{
		"name": name,
	}
	contentBytes, err := json.Marshal(content)
	if err != nil {
		return "", fmt.Errorf("failed to marshal default Kind 0 metadata content: %w", err)
	}
	return string(contentBytes), nil
}

func removeManagedKind0CryptoTags(tags nostrpkg.Tags) nostrpkg.Tags {
	managed := managedKind0CryptoTagNames()
	kept := make(nostrpkg.Tags, 0, len(tags))
	for _, tag := range tags {
		if len(tag) > 0 {
			if _, ok := managed[tag[0]]; ok {
				continue
			}
		}
		kept = append(kept, tag)
	}
	return kept
}

// normalizeRelayURL prepends wss:// when no scheme is present; accepts wss:// and ws:// as-is.
func normalizeRelayURL(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	if strings.HasPrefix(s, "wss://") || strings.HasPrefix(s, "ws://") {
		return s
	}
	return "wss://" + s
}

// parseRelayURLs splits a comma-separated relay string and returns normalized wss:// URLs.
// Empty entries are skipped.
func parseRelayURLs(relaysStr string) []string {
	if relaysStr == "" {
		return nil
	}
	parts := strings.Split(relaysStr, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		url := normalizeRelayURL(p)
		if url != "" {
			out = append(out, url)
		}
	}
	return out
}

// generateDNSRecord parses the key, derives addresses, and returns the dnsRecord and Nostr keys.
//
//nolint:funlen
func generateDNSRecord(keyPath string, seedPassphrase string) (*dnsRecord, *seedify.NostrKeys, error) {
	// Parse the key (same pattern as generateUnifiedOutput)
	f, err := openFileOrStdin(keyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("could not read key: %w", err)
	}
	defer f.Close() //nolint:errcheck
	bts, err := io.ReadAll(f)
	if err != nil {
		return nil, nil, fmt.Errorf("could not read key: %w", err)
	}

	// Check if key is password-protected (required for this command)
	isProtected, err := isKeyPasswordProtected(bts)
	if err == nil && !isProtected {
		return nil, nil, errors.New("key is not password-protected: keys are required to be password-protected")
	}

	var sourcePass []byte
	key, err := parsePrivateKey(bts, nil)
	if err != nil && isPasswordError(err) {
		sourcePass, err = askKeyPassphrase(keyPath)
		if err != nil {
			return nil, nil, err
		}
		key, err = parsePrivateKey(bts, sourcePass)
		if err != nil {
			return nil, nil, fmt.Errorf("could not parse key with passphrase: %w", err)
		}
	} else if err != nil {
		return nil, nil, fmt.Errorf("could not parse key: %w", err)
	}

	ed25519Key, ok := key.(*ed25519.PrivateKey)
	if !ok {
		return nil, nil, unsupportedKeyTypeError(key)
	}

	ed25519Key, _, err = activateBrainBunkerSSHKey(ed25519Key, bts, seedPassphrase, sourcePass, brainBunkerKeyPassphrase)
	if err != nil {
		return nil, nil, err
	}
	seedPassphrase = ""

	// Encode SSH public key for the DNS record.
	sshPubKey, pubErr := ssh.NewPublicKey(ed25519Key.Public())
	if pubErr != nil {
		return nil, nil, fmt.Errorf("failed to create SSH public key: %w", pubErr)
	}
	sshEd25519PubKey := base64.StdEncoding.EncodeToString(sshPubKey.Marshal())

	mnemonic, err := seedify.ToMnemonicWithLength(ed25519Key, 24, seedPassphrase, false, 0) //nolint:mnd
	if err != nil {
		return nil, nil, fmt.Errorf("could not generate 24-word mnemonic: %w", err)
	}

	nostrKeys, err := seedify.DeriveNostrKeysWithHex(mnemonic, bip39Passphrase)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to derive Nostr keys: %w", err)
	}

	zentenProfileDate := time.Now().UTC()
	btcAddr, _, err := zentenProfileBitcoinAddress(mnemonic)
	if err != nil {
		return nil, nil, err
	}

	sp1Addr, err := seedify.DeriveSilentPaymentAddress(mnemonic, bip39Passphrase)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to derive Silent Payment (sp1) address: %w", err)
	}

	payNymKeys, err := seedify.DerivePayNym(mnemonic, bip39Passphrase)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to derive PayNym: %w", err)
	}

	ltcAddr, err := seedify.DeriveLitecoinAddress(mnemonic, bip39Passphrase)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to derive Litecoin address: %w", err)
	}

	dogeAddr, err := seedify.DeriveDogecoinAddress(mnemonic, bip39Passphrase)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to derive Dogecoin address: %w", err)
	}

	polyseedMnemonic, err := seedify.ToMnemonicWithLength(ed25519Key, 16, seedPassphrase, false, birthdayFromDate(zentenProfileDate)) //nolint:mnd
	if err != nil {
		return nil, nil, fmt.Errorf("could not generate current-day 16-word polyseed: %w", err)
	}
	xmrAddr, _, err := zentenProfileMoneroSubaddress(polyseedMnemonic)
	if err != nil {
		return nil, nil, err
	}

	cosmosAddr, err := seedify.DeriveCosmosAddress(mnemonic, bip39Passphrase)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to derive Cosmos address: %w", err)
	}

	nobleAddr, err := seedify.DeriveNobleAddress(mnemonic, bip39Passphrase)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to derive Noble address: %w", err)
	}

	ethAddr, err := seedify.DeriveEthereumAddress(mnemonic, bip39Passphrase)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to derive Ethereum address: %w", err)
	}

	zcashAddr, err := seedify.DeriveZcashAddress(mnemonic, bip39Passphrase)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to derive Zcash address: %w", err)
	}

	solAddr, err := seedify.DeriveSolanaAddress(mnemonic, bip39Passphrase)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to derive Solana address: %w", err)
	}

	suiAddr, err := seedify.DeriveSuiAddress(mnemonic, bip39Passphrase)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to derive Sui address: %w", err)
	}

	tronAddr, err := seedify.DeriveTronAddress(mnemonic, bip39Passphrase)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to derive Tron address: %w", err)
	}

	xlmAddr, err := seedify.DeriveStellarAddress(mnemonic, bip39Passphrase)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to derive Stellar address: %w", err)
	}

	xrpAddr, err := seedify.DeriveRippleAddress(mnemonic, bip39Passphrase)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to derive Ripple address: %w", err)
	}

	record := &dnsRecord{
		SSHEd25519:    sshEd25519PubKey,
		Nostr:         nostrKeys.Npub,
		Npub:          nostrKeys.Npub,
		NpubKey:       nostrKeys.Npub,
		PubKey:        nostrKeys.PubKeyHex,
		HexPub:        nostrKeys.PubKeyHex,
		HexPubKey:     nostrKeys.PubKeyHex,
		Bitcoin:       btcAddr,
		SilentPayment: sp1Addr,
		PayNym:        payNymKeys.PaymentCode,
		Litecoin:      ltcAddr,
		Dogecoin:      dogeAddr,
		Monero:        xmrAddr,
		Cosmos:        cosmosAddr,
		Noble:         nobleAddr,
		Arbitrum:      ethAddr,
		Avalanche:     ethAddr,
		Base:          ethAddr,
		BNBChain:      ethAddr,
		Celo:          ethAddr,
		Cronos:        ethAddr,
		Ethereum:      ethAddr,
		HyperEVM:      ethAddr,
		Zcash:         zcashAddr,
		Optimism:      ethAddr,
		Polygon:       ethAddr,
		Solana:        solAddr,
		Sui:           suiAddr,
		Tron:          tronAddr,
		Stellar:       xlmAddr,
		Ripple:        xrpAddr,
	}
	return record, nostrKeys, nil
}

func zentenProfileBitcoinAddress(mnemonic string) (string, uint32, error) {
	index, indexErr := zentenProfileRandomIndex(1, zentenProfileBitcoinDailyAddressMax)
	if indexErr != nil {
		return "", 0, indexErr
	}
	addr, err := seedify.DeriveBitcoinAddressNativeSegwitAtIndex(mnemonic, bip39Passphrase, index)
	if err != nil {
		return "", 0, fmt.Errorf("failed to derive Bitcoin native SegWit address at index %d: %w", index, err)
	}
	return addr, index, nil
}

func zentenProfileMoneroSubaddress(polyseedMnemonic string) (string, uint32, error) {
	index, indexErr := zentenProfileRandomIndex(1, zentenProfileMoneroDailySubaddressMax)
	if indexErr != nil {
		return "", 0, indexErr
	}
	addr, err := seedify.DeriveMoneroSubaddressAtIndex(polyseedMnemonic, index-1)
	if err != nil {
		return "", 0, fmt.Errorf("failed to derive Monero subaddress %d: %w", index, err)
	}
	return addr, index, nil
}

func buildKind0CryptoTagsEvent(existing *nostrpkg.Event, record *dnsRecord, nostrKeys *seedify.NostrKeys, labels string, createdAt nostrpkg.Timestamp) (*nostrpkg.Event, error) {
	content, contentErr := defaultKind0Content(nostrKeys)
	if contentErr != nil {
		return nil, contentErr
	}
	tags := nostrpkg.Tags{}
	if existing != nil {
		content = existing.Content
		tags = removeManagedKind0CryptoTags(existing.Tags)
	}
	tags = append(tags, tagsToNostrTags(kind0CryptoTags(*record, labels))...)

	ev := &nostrpkg.Event{
		PubKey:    nostrKeys.PubKeyHex,
		CreatedAt: createdAt,
		Kind:      kindNostrProfileMetadata,
		Tags:      tags,
		Content:   content,
	}
	if err := ev.Sign(nostrKeys.PrivKeyHex); err != nil {
		return nil, fmt.Errorf("failed to sign Kind 0 metadata event: %w", err)
	}
	return ev, nil
}

func latestKind0Event(events []*nostrpkg.Event) *nostrpkg.Event {
	var latest *nostrpkg.Event
	for _, ev := range events {
		if ev == nil {
			continue
		}
		if latest == nil || ev.CreatedAt > latest.CreatedAt {
			latest = ev
		}
	}
	return latest
}

func fetchLatestKind0Event(ctx context.Context, relay *nostrpkg.Relay, pubkey string) (*nostrpkg.Event, error) {
	events, err := relay.QuerySync(ctx, nostrpkg.Filter{
		Authors: []string{pubkey},
		Kinds:   []int{kindNostrProfileMetadata},
		Limit:   1,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to query latest Kind 0 metadata event: %w", err)
	}
	return latestKind0Event(events), nil
}

func fetchLatestKind0EventWithAuth(ctx context.Context, relay *nostrpkg.Relay, pubkey string, nostrKeys *seedify.NostrKeys, relayURL string) (*nostrpkg.Event, error) {
	existing, err := fetchLatestKind0Event(ctx, relay, pubkey)
	if err == nil || !isNostrAuthRequiredError(err) {
		return existing, err
	}

	fmt.Fprintf(os.Stderr, "seedify: relay %s requires authentication before fetching Kind 0 metadata event: %v\n", relayURL, err)
	if authErr := authenticateNostrRelay(ctx, relay, nostrKeys, relayURL); authErr != nil {
		return nil, authErr
	}
	return fetchLatestKind0Event(ctx, relay, pubkey)
}

func isNostrRateLimitError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "rate-limited") || strings.Contains(msg, "rate limited") || strings.Contains(msg, "too much")
}

func isNostrAuthRequiredError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "auth-required:") ||
		strings.Contains(msg, "auth required") ||
		strings.Contains(msg, "authentication required") ||
		strings.Contains(msg, "restricted: authentication")
}

func authenticateNostrRelay(ctx context.Context, relay *nostrpkg.Relay, nostrKeys *seedify.NostrKeys, relayURL string) error {
	fmt.Fprintf(os.Stderr, "seedify: authenticating to %s with NIP-42\n", relayURL)
	if err := relay.Auth(ctx, func(event *nostrpkg.Event) error {
		return event.Sign(nostrKeys.PrivKeyHex)
	}); err != nil {
		return fmt.Errorf("failed to authenticate to %s: %w", relayURL, err)
	}
	fmt.Fprintf(os.Stderr, "seedify: authenticated to %s with NIP-42\n", relayURL)
	return nil
}

func nostrPublishBackoff(attempt int) time.Duration {
	switch attempt {
	case 1:
		return nostrPublishFirstRateLimitBackoff
	case nostrPublishSecondRetryAttempt:
		return nostrPublishSecondRateLimitBackoff
	default:
		return nostrPublishMaxRateLimitBackoff
	}
}

func sleepWithContext(ctx context.Context, delay time.Duration) error {
	select {
	case <-ctx.Done():
		return fmt.Errorf("context canceled while sleeping: %w", ctx.Err())
	case <-time.After(delay):
		return nil
	}
}

func publishNostrEventWithBackoff(ctx context.Context, relay *nostrpkg.Relay, ev *nostrpkg.Event, relayURL string, label string) error {
	var lastErr error
	for attempt := 0; attempt <= nostrPublishMaxRetries; attempt++ {
		if attempt > 0 {
			backoff := nostrPublishBackoff(attempt)
			fmt.Fprintf(os.Stderr, "seedify: rate-limited publishing %s to %s; retrying in %s (attempt %d/%d)\n", label, relayURL, backoff, attempt, nostrPublishMaxRetries)
			if err := sleepWithContext(ctx, backoff); err != nil {
				return err
			}
		}

		if err := relay.Publish(ctx, *ev); err != nil {
			lastErr = err
			if isNostrRateLimitError(err) && attempt < nostrPublishMaxRetries {
				continue
			}
			return fmt.Errorf("failed to publish %s to %s: %w", label, relayURL, err)
		}
		return nil
	}
	return fmt.Errorf("failed to publish %s to %s: %w", label, relayURL, lastErr)
}

func publishNostrEventWithAuthAndBackoff(ctx context.Context, relay *nostrpkg.Relay, ev *nostrpkg.Event, nostrKeys *seedify.NostrKeys, relayURL string, label string) error {
	err := publishNostrEventWithBackoff(ctx, relay, ev, relayURL, label)
	if err == nil || !isNostrAuthRequiredError(err) {
		return err
	}

	fmt.Fprintf(os.Stderr, "seedify: relay %s requires authentication before publishing %s: %v\n", relayURL, label, err)
	if authErr := authenticateNostrRelay(ctx, relay, nostrKeys, relayURL); authErr != nil {
		return authErr
	}
	return publishNostrEventWithBackoff(ctx, relay, ev, relayURL, label)
}

func publishKind0EventWithBackoff(ctx context.Context, relay *nostrpkg.Relay, ev *nostrpkg.Event, relayURL string) error {
	return publishNostrEventWithBackoff(ctx, relay, ev, relayURL, "Kind 0 metadata event")
}

func publishKind0EventWithAuthAndBackoff(ctx context.Context, relay *nostrpkg.Relay, ev *nostrpkg.Event, nostrKeys *seedify.NostrKeys, relayURL string) error {
	return publishNostrEventWithAuthAndBackoff(ctx, relay, ev, nostrKeys, relayURL, "Kind 0 metadata event")
}

// publishKind0CryptoTagsToRelays fetches each relay's latest Kind 0 metadata event,
// preserves its content and unmanaged tags, replaces all seedify-managed crypto tags,
// and publishes a new Kind 0 event with current crypto address tags.
func publishKind0CryptoTagsToRelays(record *dnsRecord, nostrKeys *seedify.NostrKeys, relays []string, labels string) error {
	ctx, cancel := context.WithTimeout(context.Background(), nostrPublishTimeout)
	defer cancel()

	publishedAny := false
	for _, url := range relays {
		fmt.Fprintf(os.Stderr, "seedify: connecting to %s for Kind 0 metadata update\n", url)
		relay, err := nostrpkg.RelayConnect(ctx, url)
		if err != nil {
			fmt.Fprintf(os.Stderr, "seedify: failed to connect to %s for Kind 0 metadata update: %v\n", url, err)
			continue
		}

		fmt.Fprintf(os.Stderr, "seedify: fetching current Kind 0 metadata event from %s\n", url)
		existing, err := fetchLatestKind0EventWithAuth(ctx, relay, nostrKeys.PubKeyHex, nostrKeys, url)
		if err != nil {
			fmt.Fprintf(os.Stderr, "seedify: failed to fetch Kind 0 metadata event from %s: %v\n", url, err)
			continue
		}

		ev, err := buildKind0CryptoTagsEvent(existing, record, nostrKeys, labels, nostrpkg.Now())
		if err != nil {
			return err
		}

		fmt.Fprintf(os.Stderr, "seedify: publishing Kind 0 metadata event with crypto address tags to %s\n", url)
		if err := publishKind0EventWithAuthAndBackoff(ctx, relay, ev, nostrKeys, url); err != nil {
			fmt.Fprintf(os.Stderr, "seedify: failed to publish Kind 0 metadata event to %s: %v\n", url, err)
			continue
		}
		fmt.Fprintf(os.Stderr, "seedify: published Kind 0 metadata event with crypto address tags to %s\n", url)
		publishedAny = true
	}

	if !publishedAny {
		return errors.New("failed to publish Kind 0 metadata event to any relay")
	}
	return nil
}
