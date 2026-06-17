// Package main provides the seedify CLI tool for generating seed phrases from SSH keys.
package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
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
	mcobra "github.com/muesli/mango-cobra"
	"github.com/muesli/roff"
	"github.com/muesli/termenv"
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

	language        string
	wordCountStr    string
	seedPassphrase  string
	brave           bool
	full            bool
	nostr           bool
	bitcoin         bool
	ethereum        bool
	zcash           bool
	solana          bool
	tron            bool
	monero          bool
	moneroLegacy    bool
	beldex          bool
	zenprofile      bool
	publishRelays   string
	zenprofileAppID string
	polyseedYear    string
	polyseedMonth   string
	polyseedAll     bool

	// derive-key flags.
	deriveKeyToRSA           bool
	deriveKeyToDKIM          bool
	deriveKeyToOnion         bool
	deriveKeyToI2P           bool
	deriveKeyToWireGuard     bool
	deriveKeyPKCS8           bool
	deriveKeyToPGP           bool
	deriveKeyPGPName         string
	deriveKeyPGPEmail        string
	deriveKeyOutput          string
	deriveKeyBits            int
	deriveKeyDKIMSelector    string
	deriveKeyDKIMDomain      string
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
  seedify ~/.ssh/id_ed25519 --words 12 --seed-passphrase "my-passphrase"
  seedify ~/.ssh/id_ed25519 --brave
  seedify ~/.ssh/id_ed25519 --full
  seedify ~/.ssh/id_ed25519 --polyseed-year 2024
  seedify ~/.ssh/id_ed25519 --polyseed-year 2024 --polyseed-month 6
  seedify ~/.ssh/id_ed25519 --xmr --polyseed-year 2025
  seedify ~/.ssh/id_ed25519 --xmr --polyseed-year 2025 --polyseed-month 3
  cat ~/.ssh/id_ed25519 | seedify --words 18
  seedify ~/.ssh/id_ed25519 --to-rsa --output ~/.ssh/id_rsa_derived
  seedify ~/.ssh/id_ed25519 --to-rsa --reuse-passphrase --output ~/.ssh/id_rsa_derived
  seedify ~/.ssh/id_ed25519 --to-rsa --openssl-compatible --output ~/.ssh/id_rsa_derived.pem
  seedify ~/.ssh/id_ed25519 --to-dkim --output /etc/opendkim/keys/mail.private
  seedify ~/.ssh/id_ed25519 --to-dkim --dkim-selector mail --dkim-domain example.com --output /etc/opendkim/keys/mail.private
  seedify deployment-ssh-key --to-dkim --dkim-domain mail1.npub.cx --dkim-selector mail2026`,
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
			// fresh output passphrase: --to-rsa and --to-pgp.
			if deriveKeyReusePassphrase && !deriveKeyToRSA && !deriveKeyToPGP {
				return errors.New("--reuse-passphrase requires --to-rsa or --to-pgp")
			}

			// --to-pgp is mutually exclusive with --to-rsa and --to-dkim.
			if deriveKeyToPGP && (deriveKeyToRSA || deriveKeyToDKIM) {
				return errors.New("--to-pgp cannot be combined with --to-rsa or --to-dkim")
			}

			// --to-onion is mutually exclusive with all other derivation modes.
			if deriveKeyToOnion && (deriveKeyToRSA || deriveKeyToDKIM || deriveKeyToPGP) {
				return errors.New("--to-onion cannot be combined with --to-rsa, --to-dkim, or --to-pgp")
			}

			// --to-i2p is mutually exclusive with all other derivation modes.
			if deriveKeyToI2P && (deriveKeyToRSA || deriveKeyToDKIM || deriveKeyToPGP || deriveKeyToOnion) {
				return errors.New("--to-i2p cannot be combined with --to-rsa, --to-dkim, --to-pgp, or --to-onion")
			}

			// --to-wireguard is mutually exclusive with all other derivation modes.
			if deriveKeyToWireGuard && (deriveKeyToRSA || deriveKeyToDKIM || deriveKeyToPGP || deriveKeyToOnion || deriveKeyToI2P) {
				return errors.New("--to-wireguard cannot be combined with --to-rsa, --to-dkim, --to-pgp, --to-onion, or --to-i2p")
			}

			// --pgp-name and --pgp-email are both required when --to-pgp is set.
			if deriveKeyToPGP && deriveKeyPGPName == "" {
				return errors.New("--pgp-name is required with --to-pgp")
			}
			if deriveKeyToPGP && deriveKeyPGPEmail == "" {
				return errors.New("--pgp-email is required with --to-pgp")
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

			// Handle --to-pgp: derive an OpenPGP RSA keypair and write an ASCII-armored .asc file.
			if deriveKeyToPGP {
				return runDerivePGPKey(keyPath)
			}

			// --publish requires --zenprofile
			if publishRelays != "" && !zenprofile {
				return errors.New("--publish requires --zenprofile")
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

			// Handle --zenprofile flag: output public keys and addresses as DNS JSON
			// This is a special case that bypasses the unified output
			if zenprofile {
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
						if err := publishDNSToRelays(record, nostrKeys, relays); err != nil {
							if strings.Contains(err.Error(), "key is not password-protected") {
								return formatPasswordError(err)
							}
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
					err = generateUnifiedOutput(keyPath, parsedCounts, seedPassphrase,
						false, false, false, false, false, false, false, false, false, false, false)
					if err != nil {
						if strings.Contains(err.Error(), "key is not password-protected") {
							return formatPasswordError(err)
						}
						return err
					}
				} else if hasDerivationFlags {
					wc := buildWordCounts(bitcoin, ethereum, zcash, solana, tron, nostr, monero, polyseedAll)
					err := generateUnifiedOutput(keyPath, wc, seedPassphrase,
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
			hasCryptoFlags := bitcoin || ethereum || zcash || solana || tron || monero || moneroLegacy || beldex || polyseedAll || zenprofile
			hasAnyDerivationFlags := hasWordsFlag || hasNostrFlag || hasCryptoFlags

			var wordCounts []int
			var deriveNostr bool
			var showBrave bool
			var deriveBtc, deriveEth, deriveZec, deriveSol, deriveTron, deriveXmr, deriveXmrLegacy, deriveBdx bool

			if !hasAnyDerivationFlags {
				wordCounts = []int{12, 15, 16, 18, 21, 24}
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

			uErr := generateUnifiedOutput(keyPath, wordCounts, seedPassphrase, deriveNostr, showBrave, deriveBtc, deriveEth, deriveZec, deriveSol, deriveTron, deriveXmr, deriveXmrLegacy, deriveBdx, true)
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
	rootCmd.PersistentFlags().StringVar(&seedPassphrase, "seed-passphrase", "", "Passphrase to combine with SSH key seed for additional entropy")
	rootCmd.PersistentFlags().BoolVar(&brave, "brave", false, "Generate 25-word phrase with Brave Sync")
	rootCmd.PersistentFlags().BoolVar(&full, "full", false, "Print full output (all word counts, Nostr keys, crypto derivations)")
	rootCmd.PersistentFlags().BoolVar(&nostr, "nostr", false, "Derive Nostr keys (npub/nsec) from seed phrase.")
	rootCmd.PersistentFlags().BoolVar(&bitcoin, "btc", false, "Derive Bitcoin address from 24-word seed phrase")
	rootCmd.PersistentFlags().BoolVar(&ethereum, "eth", false, "Derive Ethereum address from 24-word seed phrase")
	rootCmd.PersistentFlags().BoolVar(&zcash, "zec", false, "Derive Zcash address from 24-word seed phrase")
	rootCmd.PersistentFlags().BoolVar(&solana, "sol", false, "Derive Solana address from 24-word seed phrase")
	rootCmd.PersistentFlags().BoolVar(&tron, "tron", false, "Derive Tron address from 24-word seed phrase")
	rootCmd.PersistentFlags().BoolVar(&monero, "xmr", false, "Derive Monero address from 16-word polyseed")
	rootCmd.PersistentFlags().BoolVar(&moneroLegacy, "xmr-legacy", false, "Derive Monero address from 25-word legacy seed (shown alongside --xmr polyseed output)")
	rootCmd.PersistentFlags().BoolVar(&beldex, "bdx", false, "Derive Beldex (BDX) address from 25-word legacy seed (same seed format as --xmr-legacy)")
	rootCmd.PersistentFlags().BoolVar(&zenprofile, "zenprofile", false, "Output public keys and addresses as DNS JSON to stdout")
	rootCmd.PersistentFlags().StringVar(&publishRelays, "publish", "", "When used with --zenprofile: publish NIP-78 Kind 30078 event to these relays (comma-separated, e.g. relay.primal.net,relay.damus.io)")
	rootCmd.PersistentFlags().StringVar(&zenprofileAppID, "zenprofile-app-id", "app.zenprofile.identifier", "When used with --zenprofile --publish: NIP-78 d tag value for the event identifier")
	rootCmd.PersistentFlags().StringVar(&polyseedYear, "polyseed-year", "", "Override polyseed year (YYYY). Default: current year")
	rootCmd.PersistentFlags().StringVar(&polyseedMonth, "polyseed-month", "", "Override polyseed month (1-12). Default: 1 (January)")
	rootCmd.PersistentFlags().BoolVar(&polyseedAll, "all-polyseeds", false, "Generate every possible polyseed (Nov 2021 – current month), one per month with correct birthday")
	rootCmd.PersistentFlags().BoolVar(&deriveKeyToRSA, "to-rsa", false, "Derive an RSA key from the input Ed25519 key and write it to --output")
	rootCmd.PersistentFlags().BoolVar(&deriveKeyToDKIM, "to-dkim", false, "Derive a DKIM RSA keypair from the input Ed25519 key; when --dkim-domain is set, writes config/dkim/<domain>/<selector>.private and .public automatically")
	rootCmd.PersistentFlags().BoolVar(&deriveKeyToOnion, "to-onion", false, "Derive a Tor v3 hidden service identity from the input Ed25519 key; use --output <dir> to write the Tor key files")
	rootCmd.PersistentFlags().BoolVar(&deriveKeyToI2P, "to-i2p", false, "Derive an I2P Destination (Ed25519 signing + X25519 encryption) from the input Ed25519 key; use --output <dir> to write the keys.dat file")
	rootCmd.PersistentFlags().BoolVar(&deriveKeyToWireGuard, "to-wireguard", false, "Derive a WireGuard static keypair from the input Ed25519 key; prints private and public keys in base64 (wg format)")
	rootCmd.PersistentFlags().BoolVar(&deriveKeyPKCS8, "openssl-compatible", false, "Write an encrypted PKCS#8 PEM file instead of OpenSSH format (used with --to-rsa; compatible with openssl pkey -check)")
	rootCmd.PersistentFlags().BoolVar(&deriveKeyToPGP, "to-pgp", false, "Derive an OpenPGP RSA keypair and write an ASCII-armored secret key (.asc) to --output")
	rootCmd.PersistentFlags().StringVar(&deriveKeyPGPName, "pgp-name", "", "Full name for the OpenPGP UID, e.g. Alice (used with --to-pgp)")
	rootCmd.PersistentFlags().StringVar(&deriveKeyPGPEmail, "pgp-email", "", "Email address for the OpenPGP UID, e.g. alice@example.com (used with --to-pgp)")
	rootCmd.PersistentFlags().StringVar(&deriveKeyOutput, "output", "", "Output file path for the derived key (used with --to-rsa, --to-dkim, or --to-pgp)")
	rootCmd.PersistentFlags().IntVar(&deriveKeyBits, "bits", 4096, "RSA key size in bits (2048, 3072, or 4096); used with --to-rsa, --to-dkim, or --to-pgp") //nolint:mnd
	rootCmd.PersistentFlags().StringVar(&deriveKeyDKIMSelector, "dkim-selector", "mail", "DKIM selector name for the DNS TXT record (used with --to-dkim)")
	rootCmd.PersistentFlags().StringVar(&deriveKeyDKIMDomain, "dkim-domain", "", "Domain for the DKIM DNS TXT record label, e.g. example.com (used with --to-dkim)")
	rootCmd.PersistentFlags().BoolVar(&deriveKeyReusePassphrase, "reuse-passphrase", false, "Reuse the source key's passphrase to protect the derived key (used with --to-rsa or --to-pgp); requires the source key to be password-protected")
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
	return uint64(time.Date(year, month, 1, 0, 0, 0, 0, time.UTC).Unix()) //nolint:gosec
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
		birthday := uint64(current.Unix()) //nolint:gosec
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

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

// getDefaultSSHDir returns the default SSH directory for the current platform.
// On Unix-like systems (Linux, macOS), this is ~/.ssh/.
// On Windows, this is %USERPROFILE%\.ssh\.
func getDefaultSSHDir() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("could not get home directory: %w", err)
	}
	return filepath.Join(homeDir, ".ssh"), nil
}

// resolveKeyPath attempts to resolve a key path. If the path doesn't exist
// and appears to be just a filename (no directory separators), it will check
// the default SSH directory for a key with that name.
func resolveKeyPath(path string) (string, error) {
	// If path is "-", use it as-is
	if path == "-" {
		return path, nil
	}

	// Check if the path exists as-is
	if _, err := os.Stat(path); err == nil {
		return path, nil
	}

	// Check if path is just a filename (no directory separators)
	// Clean the path first to normalize it, then check if the directory
	// component is "." (current directory) or empty
	cleanedPath := filepath.Clean(path)
	dir := filepath.Dir(cleanedPath)

	// If the directory is not "." or empty, it's a path with directory components
	// - don't check default SSH directory
	if dir != "." && dir != "" {
		return "", fmt.Errorf("could not open %s: %w", path, os.ErrNotExist)
	}

	// Also check if the original path explicitly starts with relative path indicators
	// These are relative paths that should not be checked in default SSH directory
	// Check for both Unix-style (./, ../) and Windows-style (.\, ..\) prefixes
	pathLower := strings.ToLower(path)
	if strings.HasPrefix(pathLower, "./") || strings.HasPrefix(pathLower, "../") ||
		strings.HasPrefix(pathLower, ".\\") || strings.HasPrefix(pathLower, "..\\") {
		return "", fmt.Errorf("could not open %s: %w", path, os.ErrNotExist)
	}

	// Path appears to be just a filename, try default SSH directory
	sshDir, err := getDefaultSSHDir()
	if err != nil {
		return "", fmt.Errorf("could not determine SSH directory: %w", err)
	}

	// Use the cleaned path (or original if it's just a filename) to construct the default path
	filename := filepath.Base(cleanedPath)
	defaultPath := filepath.Join(sshDir, filename)

	// Check if the file exists in the default SSH directory
	if _, err := os.Stat(defaultPath); err == nil {
		return defaultPath, nil
	}

	// Key not found — exit with a warning rather than attempting to generate one
	return "", fmt.Errorf("warning: key not found: %s does not exist in the current directory or %s", path, sshDir)
}

func openFileOrStdin(path string) (*os.File, error) {
	if path == "-" {
		return os.Stdin, nil
	}

	if fi, _ := os.Stdin.Stat(); (fi.Mode() & os.ModeNamedPipe) != 0 {
		return os.Stdin, nil
	}

	// Resolve the key path (check default SSH directory if needed)
	resolvedPath, err := resolveKeyPath(path)
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

// generateBraveSyncPhrase generates a 25-word seed phrase with Brave Sync.
// seedPassphrase is combined with the SSH key seed to add additional entropy.
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

	key, err := parsePrivateKey(bts, nil)
	if err != nil && isPasswordError(err) {
		// Key requires a password - ask for it and parse again with the same bytes
		pass, err := askKeyPassphrase(path)
		if err != nil {
			return "", err
		}
		// Parse again with the password using the bytes we already have
		key, err = parsePrivateKey(bts, pass)
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
	fmt.Printf("-----BEGIN %s-----\n%s\n-----END %s-----\n", label, phrase, label)
}

// printSSHKeyPair prints the SSH public key (RFC 4716 OpenSSH PEM) with the
// key type prepended inside the block (ssh-ed25519 <base64> <npub>), the
// private key (OpenSSH PEM) with its SHA-256 hash, the raw 32-byte ed25519
// seed in hex with its SHA-256 hash, and the SHA-256 fingerprint of the public
// key. npub is appended as the authorized_keys-style comment on the public key
// line. privateKeyPEM must be the raw PEM bytes as read from disk.
func printSSHKeyPair(ed25519Key *ed25519.PrivateKey, privateKeyPEM []byte, npub string) error {
	sshPubKey, err := ssh.NewPublicKey(ed25519Key.Public())
	if err != nil {
		return fmt.Errorf("failed to encode SSH public key: %w", err)
	}

	pubB64 := base64.StdEncoding.EncodeToString(sshPubKey.Marshal())
	fmt.Printf("-----BEGIN OPENSSH PUBLIC KEY-----\nssh-ed25519 %s %s\n-----END OPENSSH PUBLIC KEY-----\n", pubB64, npub)

	// pem.Decode extracts the raw OpenSSH key bytes so we can re-encode them
	// as a single unwrapped base64 line instead of the default 64-char wrapping.
	block, _ := pem.Decode(privateKeyPEM)
	if block == nil {
		return errors.New("failed to decode private key PEM block")
	}

	privB64 := base64.StdEncoding.EncodeToString(block.Bytes)
	fmt.Printf("\n-----BEGIN OPENSSH PRIVATE KEY-----\n%s\n-----END OPENSSH PRIVATE KEY-----\n", privB64)

	privHash := sha256.Sum256([]byte(privB64))
	fmt.Printf("\n-----BEGIN OPENSSH PRIVATE KEY HASH-----\n%s\n-----END OPENSSH PRIVATE KEY HASH-----\n", hex.EncodeToString(privHash[:]))

	// Raw 32-byte seed — the root secret from which the key pair is derived.
	seedBytes := ed25519Key.Seed()
	seedHex := hex.EncodeToString(seedBytes)
	fmt.Printf("\n-----BEGIN ED25519 SEED-----\n%s\n-----END ED25519 SEED-----\n", seedHex)

	seedHash := sha256.Sum256(seedBytes)
	fmt.Printf("\n-----BEGIN ED25519 SEED HASH-----\n%s\n-----END ED25519 SEED HASH-----\n", hex.EncodeToString(seedHash[:]))

	// SHA-256 fingerprint in the standard ssh-keygen format (SHA256:<base64>).
	sha256fp := ssh.FingerprintSHA256(sshPubKey)
	fmt.Printf("\n-----BEGIN OPENSSH FINGERPRINT-----\n%s\n-----END OPENSSH FINGERPRINT-----\n", sha256fp)

	return nil
}

// generatePhrasesOutput generates a curated set of seed phrases from the SSH key.
// It prints the following phrases in order:
//  1. 12-word BIP39 seed phrase
//  2. 16-word Polyseed seed phrase
//  3. 24-word BIP39 seed phrase
//  4. Nostr keys derived from the 24-word mnemonic (NIP-06 path)
//  5. Brave 25-word seed phrase (24 brave-prefixed words + 25th word)
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

	key, err := parsePrivateKey(bts, nil)
	if err != nil && isPasswordError(err) {
		// Key requires a password - ask for it and parse again with the same bytes
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

	// Pre-derive the 24-word mnemonic and Nostr keys so the npub can be used
	// as the public key comment before printing the SSH key pair.
	mnemonic24, err := seedify.ToMnemonicWithLength(ed25519Key, 24, seedPassphrase, false, 0) //nolint:mnd
	if err != nil {
		return fmt.Errorf("could not generate 24-word mnemonic: %w", err)
	}

	nostrKeys, err := seedify.DeriveNostrKeysWithHex(mnemonic24, "")
	if err != nil {
		return fmt.Errorf("could not derive Nostr keys from 24-word mnemonic: %w", err)
	}

	fmt.Print("\n\n")
	if err := printSSHKeyPair(ed25519Key, bts, nostrKeys.Npub); err != nil {
		return err
	}

	// 1. 12-word seed phrase
	mnemonic12, err := seedify.ToMnemonicWithLength(ed25519Key, 12, seedPassphrase, false, 0) //nolint:mnd
	if err != nil {
		return fmt.Errorf("could not generate 12-word mnemonic: %w", err)
	}
	// 2 empty lines before the first output
	fmt.Print("\n\n")
	printPEMPhrase("12-WORD SEED PHRASE", mnemonic12)

	// 2. 16-word seed phrases (Polyseed).
	// When --all-polyseeds is set, iterate every calendar day from the epoch
	// and emit one PEM block per unique mnemonic, labelled with its date range.
	// Otherwise emit one block per (year, month) slot as before.
	if polyseedAll {
		dayGroups16, dgErr := groupPolyseedsByDay(ed25519Key, seedPassphrase)
		if dgErr != nil {
			return dgErr
		}
		for _, g := range dayGroups16 {
			label := fmt.Sprintf("16-WORD POLYSEED (%s → %s)",
				g.startDate.Format("2006-01-02"),
				g.endDate.Format("2006-01-02"),
			)
			fmt.Print("\n\n")
			printPEMPhrase(label, g.mnemonic)
		}
	} else {
		var slots16 []yearMonth
		years, yErr := getPolyseedYears()
		if yErr != nil {
			return fmt.Errorf("invalid --polyseed-year: %w", yErr)
		}
		month, mErr := getPolyseedMonth()
		if mErr != nil {
			return fmt.Errorf("invalid --polyseed-month: %w", mErr)
		}
		for _, y := range years {
			slots16 = append(slots16, yearMonth{year: y, month: month})
		}
		for _, slot := range slots16 {
			mnemonic16, mnErr := seedify.ToMnemonicWithLength(ed25519Key, 16, seedPassphrase, false, birthdayFromYearMonth(slot.year, slot.month)) //nolint:mnd
			if mnErr != nil {
				return fmt.Errorf("could not generate 16-word mnemonic for %d-%02d: %w", slot.year, int(slot.month), mnErr)
			}
			fmt.Print("\n\n")
			printPEMPhrase(fmt.Sprintf("16-WORD POLYSEED (1.%d.%d)", int(slot.month), slot.year), mnemonic16)
		}
	}

	// 3. 24-word seed phrase (standard, no prefix)
	// 2 empty lines between outputs
	fmt.Print("\n\n")
	printPEMPhrase("24-WORD SEED PHRASE (charmbracelet/MELT)", mnemonic24)

	// 4. Nostr keys derived from the 24-word mnemonic (NIP-06 path)
	fmt.Print("\n\n")
	fmt.Println("----- nPubKey / hexPubKey / nSecKey / hexSecKey -----")
	fmt.Println(nostrKeys.Npub)
	fmt.Println(nostrKeys.PubKeyHex)
	fmt.Println(nostrKeys.Nsec)
	fmt.Println(nostrKeys.PrivKeyHex)
	fmt.Println("----- nPubKey / hexPubKey / nSecKey / hexSecKey -----")

	// 5. Monero 25-word legacy seed (Electrum-style, "monero" prefix)
	moneroLegacySeed, err := seedify.ToMoneroLegacySeedWithPrefix(ed25519Key, seedPassphrase, "monero")
	if err != nil {
		return fmt.Errorf("could not generate Monero legacy seed: %w", err)
	}
	fmt.Print("\n\n")
	printPEMPhrase("25-WORD MONERO LEGACY SEED", moneroLegacySeed)

	// 6. Beldex 25-word seed ("beldex" prefix ensures divergence from Monero)
	bdxSeed, err := seedify.ToMoneroLegacySeedWithPrefix(ed25519Key, seedPassphrase, "beldex")
	if err != nil {
		return fmt.Errorf("could not generate Beldex seed: %w", err)
	}
	fmt.Print("\n\n")
	printPEMPhrase("25-WORD BELDEX (BDX) SEED", bdxSeed)

	// 7. Brave 25-word seed phrase (24 brave-prefixed words + 25th word)
	braveMnemonic, err := seedify.ToMnemonicWithBraveSync(ed25519Key, seedPassphrase)
	if err != nil {
		return fmt.Errorf("could not generate brave 25-word mnemonic: %w", err)
	}
	fmt.Print("\n\n")
	printPEMPhrase("25-WORD BRAVE-SYNC", braveMnemonic)

	// 2 empty lines after the last output
	fmt.Print("\n\n")

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

func completeColor(truecolor, ansi256, ansi string) string {
	//nolint: exhaustive
	switch lipgloss.ColorProfile() {
	case termenv.TrueColor:
		return truecolor
	case termenv.ANSI256:
		return ansi256
	}
	return ansi
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
func generateUnifiedOutput(keyPath string, wordCounts []int, seedPassphrase string, deriveNostr bool, showBrave bool, deriveBtc, deriveEth, deriveZec, deriveSol, deriveTron, deriveXmr, deriveXmrLegacy, deriveBdx bool, showPreamble bool) error {
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

	key, err := parsePrivateKey(bts, nil)
	if err != nil && isPasswordError(err) {
		// Key requires a password - ask for it and parse again with the same bytes
		pass, err := askKeyPassphrase(keyPath)
		if err != nil {
			return err
		}
		// Parse again with the password using the bytes we already have
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

	if showPreamble {
		if err := displayKeyPreamble(ed25519Key, bts, seedPassphrase); err != nil {
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
						xmrKeys, xmrErr := seedify.DeriveMoneroKeys(g.mnemonic, 9) //nolint:mnd
						if xmrErr != nil {
							return fmt.Errorf("failed to derive Monero keys from 16-word polyseed (%s → %s): %w",
								g.startDate.Format("2006-01-02"), g.endDate.Format("2006-01-02"), xmrErr)
						}

						fmt.Printf("[monero addresses from 16 word polyseed (%s → %s)]\n",
							g.startDate.Format("2006-01-02"), g.endDate.Format("2006-01-02"))
						fmt.Println()
						fmt.Printf("%s (primary address)\n", xmrKeys.PrimaryAddress)
						for j, subaddr := range xmrKeys.Subaddresses {
							fmt.Printf("> %s (subaddress 0,%d)\n", subaddr, j+1)
						}
						fmt.Println()
					}

					if deriveXmr || deriveXmrLegacy {
						fmt.Println("[25 word monero legacy seed]")
						fmt.Println()
						fmt.Println(g.legacySeed)
						fmt.Println()

						if err := displayMoneroLegacyAddresses(g.legacySeed); err != nil {
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

					fmt.Printf("[16 word seed phrase (%d-%02d)]\n", slot.year, int(slot.month))
					fmt.Println()
					fmt.Println(mnemonic)

					legacySeed, legacyErr := seedify.ToMoneroLegacySeedFromPolyseed(mnemonic)
					if legacyErr != nil {
						return fmt.Errorf("failed to derive Monero legacy seed from polyseed (%d-%02d): %w", slot.year, int(slot.month), legacyErr)
					}
					fmt.Println(legacySeed)
					fmt.Println()

					if deriveXmr {
						xmrKeys, xmrErr := seedify.DeriveMoneroKeys(mnemonic, 9) //nolint:mnd
						if xmrErr != nil {
							return fmt.Errorf("failed to derive Monero keys from 16-word polyseed (%d-%02d): %w", slot.year, int(slot.month), xmrErr)
						}

						fmt.Printf("[monero addresses from 16 word polyseed (%d-%02d)]\n", slot.year, int(slot.month))
						fmt.Println()
						fmt.Printf("%s (primary address)\n", xmrKeys.PrimaryAddress)
						for j, subaddr := range xmrKeys.Subaddresses {
							fmt.Printf("> %s (subaddress 0,%d)\n", subaddr, j+1)
						}
						fmt.Println()
					}

					if deriveXmr || deriveXmrLegacy {
						fmt.Println("[25 word monero legacy seed]")
						fmt.Println()
						fmt.Println(legacySeed)
						fmt.Println()

						if err := displayMoneroLegacyAddresses(legacySeed); err != nil {
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

			fmt.Printf("[%d word seed phrase]\n", count)
			fmt.Println()
			fmt.Println(mnemonic)
			fmt.Println()

			// Derive and display nostr keys for 12-word and 24-word seed phrases only
			if deriveNostr && (count == 12 || count == 24) {
				nostrKeys, nErr := seedify.DeriveNostrKeysWithHex(mnemonic, "")
				if nErr != nil {
					return fmt.Errorf("failed to derive Nostr keys from %d-word mnemonic: %w", count, nErr)
				}

				fmt.Printf("[nostr keys from %d word seed]\n", count)
				fmt.Println()
				fmt.Printf("%s (nostr public key aka \"nostr user\")\n", nostrKeys.Npub)
				fmt.Printf("└─ %s (hex)\n", nostrKeys.PubKeyHex)
				fmt.Printf("%s (nostr secret key aka \"nostr pass\")\n", nostrKeys.Nsec)
				fmt.Printf("└─ %s (hex)\n", nostrKeys.PrivKeyHex)
				fmt.Println()
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
					ethAddr, ethErr := seedify.DeriveEthereumAddress(mnemonic, "")
					if ethErr != nil {
						return fmt.Errorf("failed to derive Ethereum address from 24-word seed: %w", ethErr)
					}

					fmt.Printf("[ethereum address from 24 word seed]\n")
					fmt.Println()
					fmt.Println(ethAddr)
					fmt.Println()
				}

				// Zcash address (below Ethereum, shown when any crypto derivation is requested)
				if hasAnyCryptoFlag {
					zcashAddr, zErr := seedify.DeriveZcashAddress(mnemonic, "")
					if zErr != nil {
						return fmt.Errorf("failed to derive Zcash address from 24-word seed: %w", zErr)
					}

					fmt.Printf("[zcash address from 24 word seed]\n")
					fmt.Println()
					fmt.Println(zcashAddr)
					fmt.Println()
				}

				// Solana address
				if deriveSol {
					solAddr, solErr := seedify.DeriveSolanaAddress(mnemonic, "")
					if solErr != nil {
						return fmt.Errorf("failed to derive Solana address from 24-word seed: %w", solErr)
					}

					fmt.Printf("[solana address from 24 word seed]\n")
					fmt.Println()
					fmt.Println(solAddr)
					fmt.Println()
				}

				// Tron address
				if deriveTron {
					tronAddr, tErr := seedify.DeriveTronAddress(mnemonic, "")
					if tErr != nil {
						return fmt.Errorf("failed to derive Tron address from 24-word seed: %w", tErr)
					}

					fmt.Printf("[tron address from 24 word seed]\n")
					fmt.Println()
					fmt.Println(tronAddr)
					fmt.Println()
				}

				// EVM-compatible chain addresses (reuse Ethereum address)
				if deriveEth {
					evmAddr, evmErr := seedify.DeriveEthereumAddress(mnemonic, "")
					if evmErr != nil {
						return fmt.Errorf("failed to derive EVM address from 24-word seed: %w", evmErr)
					}

					fmt.Printf("[arbitrum address from 24 word seed]\n")
					fmt.Println()
					fmt.Println(evmAddr)
					fmt.Println()

					fmt.Printf("[avalanche address from 24 word seed]\n")
					fmt.Println()
					fmt.Println(evmAddr)
					fmt.Println()

					fmt.Printf("[base address from 24 word seed]\n")
					fmt.Println()
					fmt.Println(evmAddr)
					fmt.Println()

					fmt.Printf("[bnbchain address from 24 word seed]\n")
					fmt.Println()
					fmt.Println(evmAddr)
					fmt.Println()

					fmt.Printf("[cronos address from 24 word seed]\n")
					fmt.Println()
					fmt.Println(evmAddr)
					fmt.Println()

					fmt.Printf("[optimism address from 24 word seed]\n")
					fmt.Println()
					fmt.Println(evmAddr)
					fmt.Println()

					fmt.Printf("[polygon address from 24 word seed]\n")
					fmt.Println()
					fmt.Println(evmAddr)
					fmt.Println()
				}

				// Extra chains: only show when user requested at least one crypto derivation
				if hasAnyCryptoFlag {
					// Litecoin address (native SegWit)
					ltcAddr, ltcErr := seedify.DeriveLitecoinAddress(mnemonic, "")
					if ltcErr != nil {
						return fmt.Errorf("failed to derive Litecoin address from 24-word seed: %w", ltcErr)
					}

					fmt.Printf("[litecoin address from 24 word seed]\n")
					fmt.Println()
					fmt.Println(ltcAddr)
					fmt.Println()

					// Dogecoin address
					dogeAddr, dogeErr := seedify.DeriveDogecoinAddress(mnemonic, "")
					if dogeErr != nil {
						return fmt.Errorf("failed to derive Dogecoin address from 24-word seed: %w", dogeErr)
					}

					fmt.Printf("[dogecoin address from 24 word seed]\n")
					fmt.Println()
					fmt.Println(dogeAddr)
					fmt.Println()

					// Cosmos address
					cosmosAddr, cosmosErr := seedify.DeriveCosmosAddress(mnemonic, "")
					if cosmosErr != nil {
						return fmt.Errorf("failed to derive Cosmos address from 24-word seed: %w", cosmosErr)
					}

					fmt.Printf("[cosmos address from 24 word seed]\n")
					fmt.Println()
					fmt.Println(cosmosAddr)
					fmt.Println()

					// Noble address
					nobleAddr, nobleErr := seedify.DeriveNobleAddress(mnemonic, "")
					if nobleErr != nil {
						return fmt.Errorf("failed to derive Noble address from 24-word seed: %w", nobleErr)
					}

					fmt.Printf("[noble address from 24 word seed]\n")
					fmt.Println()
					fmt.Println(nobleAddr)
					fmt.Println()

					// Sui address
					suiAddr, suiErr := seedify.DeriveSuiAddress(mnemonic, "")
					if suiErr != nil {
						return fmt.Errorf("failed to derive Sui address from 24-word seed: %w", suiErr)
					}

					fmt.Printf("[sui address from 24 word seed]\n")
					fmt.Println()
					fmt.Println(suiAddr)
					fmt.Println()

					// Stellar address
					xlmAddr, xlmErr := seedify.DeriveStellarAddress(mnemonic, "")
					if xlmErr != nil {
						return fmt.Errorf("failed to derive Stellar address from 24-word seed: %w", xlmErr)
					}

					fmt.Printf("[stellar address from 24 word seed]\n")
					fmt.Println()
					fmt.Println(xlmAddr)
					fmt.Println()

					// Ripple address
					xrpAddr, xrpErr := seedify.DeriveRippleAddress(mnemonic, "")
					if xrpErr != nil {
						return fmt.Errorf("failed to derive Ripple address from 24-word seed: %w", xrpErr)
					}

					fmt.Printf("[ripple address from 24 word seed]\n")
					fmt.Println()
					fmt.Println(xrpAddr)
					fmt.Println()
				}
			}
		}

		// Add blank line between word counts (except after the last one, unless brave is also shown)
		if i < len(wordCounts)-1 || showBrave {
			fmt.Println()
		}
	}

	// Monero legacy uses a year-independent 25-word seed derived directly from the SSH key.
	// When the 16-word polyseed section ran, legacy output is already shown there.
	if deriveXmrLegacy && !wordCountsInclude(wordCounts, 16) { //nolint:mnd
		if err := displayMoneroLegacyOutput(ed25519Key, seedPassphrase); err != nil {
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

		fmt.Printf("[25 word brave seed phrase]\n")
		fmt.Println()
		fmt.Println(braveMnemonic)
		fmt.Println()
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

	masterExtended, err := seedify.DeriveBitcoinMasterExtendedKeys(mnemonic, "")
	if err != nil {
		return fmt.Errorf("failed to derive Bitcoin master extended keys: %w", err)
	}

	fmt.Printf("[bitcoin master extended keys from %d word seed]\n", wordCount)
	fmt.Println()
	fmt.Printf("%s (master xpub at m)\n", masterExtended.ExtendedPublicKey)
	fmt.Printf("%s (master xprv at m)\n", masterExtended.ExtendedPrivateKey)
	fmt.Println()

	// === SINGLE-SIG ADDRESSES AND PRIVATE KEYS ===

	// Legacy P2PKH (BIP44)
	legacyKeys, err := seedify.DeriveBitcoinLegacyKeys(mnemonic, "")
	if err != nil {
		return fmt.Errorf("failed to derive Bitcoin legacy keys: %w", err)
	}

	// SegWit P2SH-P2WPKH (BIP49)
	segwitKeys, err := seedify.DeriveBitcoinSegwitKeys(mnemonic, "")
	if err != nil {
		return fmt.Errorf("failed to derive Bitcoin SegWit keys: %w", err)
	}

	// Native SegWit P2WPKH (BIP84)
	nativeKeys, err := seedify.DeriveBitcoinNativeSegwitKeys(mnemonic, "")
	if err != nil {
		return fmt.Errorf("failed to derive Bitcoin native SegWit keys: %w", err)
	}

	fmt.Printf("[bitcoin addresses from %d word seed]\n", wordCount)
	fmt.Println()
	fmt.Printf("%s (legacy P2PKH - BIP44 m/44'/0'/0'/0/0)\n", legacyKeys.Address)
	fmt.Printf("%s (segwit P2SH-P2WPKH - BIP49 m/49'/0'/0'/0/0)\n", segwitKeys.Address)
	fmt.Printf("%s (native segwit P2WPKH - BIP84 m/84'/0'/0'/0/0)\n", nativeKeys.Address)
	fmt.Println()

	// === PRIVATE KEYS (WIF) ===

	fmt.Printf("[bitcoin private keys from %d word seed]\n", wordCount)
	fmt.Println()
	fmt.Printf("%s (legacy P2PKH - BIP44)\n", legacyKeys.PrivateWIF)
	fmt.Printf("%s (segwit P2SH-P2WPKH - BIP49)\n", segwitKeys.PrivateWIF)
	fmt.Printf("%s (native segwit P2WPKH - BIP84)\n", nativeKeys.PrivateWIF)
	fmt.Println()

	// === ACCOUNT-LEVEL EXTENDED KEYS ===
	// These are derived to the account level for each BIP standard
	// Import these into wallets to derive all addresses for that account

	// Legacy extended keys (xpub/xprv)
	legacyExtended, err := seedify.DeriveBitcoinLegacyExtendedKeys(mnemonic, "")
	if err != nil {
		return fmt.Errorf("failed to derive Bitcoin legacy extended keys: %w", err)
	}

	// SegWit extended keys (ypub/yprv)
	segwitExtended, err := seedify.DeriveBitcoinSegwitExtendedKeys(mnemonic, "")
	if err != nil {
		return fmt.Errorf("failed to derive Bitcoin SegWit extended keys: %w", err)
	}

	// Native SegWit extended keys (zpub/zprv)
	nativeExtended, err := seedify.DeriveBitcoinNativeSegwitExtendedKeys(mnemonic, "")
	if err != nil {
		return fmt.Errorf("failed to derive Bitcoin native SegWit extended keys: %w", err)
	}

	fmt.Printf("[bitcoin account extended public keys from %d word seed]\n", wordCount)
	fmt.Println()
	fmt.Printf("%s (legacy account xpub - BIP44 m/44'/0'/0')\n", legacyExtended.ExtendedPublicKey)
	fmt.Printf("%s (segwit account ypub - BIP49 m/49'/0'/0')\n", segwitExtended.ExtendedPublicKey)
	fmt.Printf("%s (native segwit account zpub - BIP84 m/84'/0'/0')\n", nativeExtended.ExtendedPublicKey)
	fmt.Println()

	fmt.Printf("[bitcoin account extended private keys from %d word seed]\n", wordCount)
	fmt.Println()
	fmt.Printf("%s (legacy account xprv - BIP44 m/44'/0'/0')\n", legacyExtended.ExtendedPrivateKey)
	fmt.Printf("%s (segwit account yprv - BIP49 m/49'/0'/0')\n", segwitExtended.ExtendedPrivateKey)
	fmt.Printf("%s (native segwit account zprv - BIP84 m/84'/0'/0')\n", nativeExtended.ExtendedPrivateKey)
	fmt.Println()

	// === MULTISIG 1-OF-1 ADDRESSES AND PRIVATE KEYS ===

	// Legacy multisig P2SH (BIP48)
	multisigLegacyKeys, err := seedify.DeriveBitcoinMultisigLegacyKeys(mnemonic, "")
	if err != nil {
		return fmt.Errorf("failed to derive Bitcoin multisig legacy keys: %w", err)
	}

	// SegWit multisig P2SH-P2WSH (BIP48)
	multisigSegwitKeys, err := seedify.DeriveBitcoinMultisigSegwitKeys(mnemonic, "")
	if err != nil {
		return fmt.Errorf("failed to derive Bitcoin multisig SegWit keys: %w", err)
	}

	// Native SegWit multisig P2WSH (BIP48)
	multisigNativeKeys, err := seedify.DeriveBitcoinMultisigNativeSegwitKeys(mnemonic, "")
	if err != nil {
		return fmt.Errorf("failed to derive Bitcoin multisig native SegWit keys: %w", err)
	}

	// === PAYNYM (BIP47) ===
	payNymKeys, err := seedify.DerivePayNym(mnemonic, "")
	if err != nil {
		return fmt.Errorf("failed to derive PayNym: %w", err)
	}

	fmt.Printf("[bitcoin PayNym (BIP47) from %d word seed]\n", wordCount)
	fmt.Println()
	fmt.Printf("%s (payment code - BIP47 m/47'/0'/0')\n", payNymKeys.PaymentCode)
	fmt.Printf("%s (notification address - m/47'/0'/0'/0)\n", payNymKeys.NotificationAddress)
	fmt.Println()

	fmt.Printf("[bitcoin multisig 1-of-1 addresses from %d word seed]\n", wordCount)
	fmt.Println()
	fmt.Printf("%s (legacy P2SH - BIP48 m/48'/0'/0'/0'/0/0)\n", multisigLegacyKeys.Address)
	fmt.Printf("%s (segwit P2SH-P2WSH - BIP48 m/48'/0'/0'/1'/0/0)\n", multisigSegwitKeys.Address)
	fmt.Printf("%s (native segwit P2WSH - BIP48 m/48'/0'/0'/2'/0/0)\n", multisigNativeKeys.Address)
	fmt.Println()

	fmt.Printf("[bitcoin multisig 1-of-1 private keys from %d word seed]\n", wordCount)
	fmt.Println()
	fmt.Printf("%s (legacy P2SH - BIP48)\n", multisigLegacyKeys.PrivateWIF)
	fmt.Printf("%s (segwit P2SH-P2WSH - BIP48)\n", multisigSegwitKeys.PrivateWIF)
	fmt.Printf("%s (native segwit P2WSH - BIP48)\n", multisigNativeKeys.PrivateWIF)
	fmt.Println()

	// === MULTISIG ACCOUNT-LEVEL EXTENDED KEYS ===

	// Legacy multisig extended keys (xpub/xprv)
	multisigLegacyExtended, err := seedify.DeriveBitcoinMultisigLegacyExtendedKeys(mnemonic, "")
	if err != nil {
		return fmt.Errorf("failed to derive Bitcoin multisig legacy extended keys: %w", err)
	}

	// SegWit multisig extended keys (Ypub/Yprv)
	multisigSegwitExtended, err := seedify.DeriveBitcoinMultisigSegwitExtendedKeys(mnemonic, "")
	if err != nil {
		return fmt.Errorf("failed to derive Bitcoin multisig SegWit extended keys: %w", err)
	}

	// Native SegWit multisig extended keys (Zpub/Zprv)
	multisigNativeExtended, err := seedify.DeriveBitcoinMultisigNativeSegwitExtendedKeys(mnemonic, "")
	if err != nil {
		return fmt.Errorf("failed to derive Bitcoin multisig native SegWit extended keys: %w", err)
	}

	fmt.Printf("[bitcoin multisig 1-of-1 account extended public keys from %d word seed]\n", wordCount)
	fmt.Println()
	fmt.Printf("%s (legacy account xpub - BIP48 m/48'/0'/0'/0')\n", multisigLegacyExtended.ExtendedPublicKey)
	fmt.Printf("%s (segwit account Ypub - BIP48 m/48'/0'/0'/1')\n", multisigSegwitExtended.ExtendedPublicKey)
	fmt.Printf("└─ %s (xpub)\n", multisigSegwitExtended.StandardPublicKey)
	fmt.Printf("%s (native segwit account Zpub - BIP48 m/48'/0'/0'/2')\n", multisigNativeExtended.ExtendedPublicKey)
	fmt.Printf("└─ %s (xpub)\n", multisigNativeExtended.StandardPublicKey)
	fmt.Println()

	fmt.Printf("[bitcoin multisig 1-of-1 account extended private keys from %d word seed]\n", wordCount)
	fmt.Println()
	fmt.Printf("%s (legacy account xprv - BIP48 m/48'/0'/0'/0')\n", multisigLegacyExtended.ExtendedPrivateKey)
	fmt.Printf("%s (segwit account Yprv - BIP48 m/48'/0'/0'/1')\n", multisigSegwitExtended.ExtendedPrivateKey)
	fmt.Printf("└─ %s (xprv)\n", multisigSegwitExtended.StandardPrivateKey)
	fmt.Printf("%s (native segwit account Zprv - BIP48 m/48'/0'/0'/2')\n", multisigNativeExtended.ExtendedPrivateKey)
	fmt.Printf("└─ %s (xprv)\n", multisigNativeExtended.StandardPrivateKey)
	fmt.Println()

	return nil
}

// displayMoneroLegacyOutput derives and prints the 25-word Monero legacy (Electrum-style) seed and
// the primary address plus subaddresses derived from it. Used for --xmr-legacy without polyseed output.
func displayMoneroLegacyOutput(ed25519Key *ed25519.PrivateKey, seedPassphrase string) error {
	legacySeed, legacyErr := seedify.ToMoneroLegacySeedWithPrefix(ed25519Key, seedPassphrase, "monero")
	if legacyErr != nil {
		return fmt.Errorf("failed to derive Monero legacy seed: %w", legacyErr)
	}

	fmt.Println("[25 word monero legacy seed]")
	fmt.Println()
	fmt.Println(legacySeed)
	fmt.Println()

	return displayMoneroLegacyAddresses(legacySeed)
}

// displayMoneroLegacyAddresses prints Monero primary and subaddresses from a 25-word legacy seed.
func displayMoneroLegacyAddresses(legacySeed string) error {
	legacyKeys, legacyKErr := seedify.DeriveMoneroKeysFromLegacySeed(legacySeed, 9) //nolint:mnd
	if legacyKErr != nil {
		return fmt.Errorf("failed to derive Monero keys from legacy seed: %w", legacyKErr)
	}

	fmt.Println("[monero addresses from 25 word legacy seed]")
	fmt.Println()
	fmt.Printf("%s (primary address)\n", legacyKeys.PrimaryAddress)
	for j, subaddr := range legacyKeys.Subaddresses {
		fmt.Printf("> %s (subaddress 0,%d)\n", subaddr, j+1)
	}
	fmt.Println()
	return nil
}

// displayKeyPreamble prints the SSH key pair, Tor onion address, and I2P destination before seed output.
func displayKeyPreamble(ed25519Key *ed25519.PrivateKey, bts []byte, seedPassphrase string) error {
	mnemonic24, m24Err := seedify.ToMnemonicWithLength(ed25519Key, 24, seedPassphrase, false, 0) //nolint:mnd
	if m24Err != nil {
		return fmt.Errorf("could not generate 24-word mnemonic for key comment: %w", m24Err)
	}
	nostrKeys, nkErr := seedify.DeriveNostrKeysWithHex(mnemonic24, "")
	if nkErr != nil {
		return fmt.Errorf("could not derive Nostr keys for key comment: %w", nkErr)
	}

	fmt.Print("\n\n")
	if err := printSSHKeyPair(ed25519Key, bts, nostrKeys.Npub); err != nil {
		return err
	}

	onionKeys, onionErr := seedify.DeriveOnionServiceKeys(ed25519Key)
	if onionErr != nil {
		return fmt.Errorf("could not derive Tor v3 hidden service keys: %w", onionErr)
	}
	fmt.Printf("\n-----BEGIN TOR ONION ADDRESS-----\n%s\n-----END TOR ONION ADDRESS-----\n", onionKeys.OnionAddress)

	i2pKeys, i2pErr := seedify.DeriveI2PDestinationKeys(ed25519Key)
	if i2pErr != nil {
		return fmt.Errorf("could not derive I2P destination keys: %w", i2pErr)
	}
	fmt.Printf("\n-----BEGIN I2P DESTINATION-----\n")
	fmt.Printf("B32 Address  : %s\n", i2pKeys.B32Address)
	fmt.Printf("X25519 PrivKey (hex): %x\n", i2pKeys.X25519PrivKey)
	fmt.Printf("Ed25519 Seed  (hex): %x\n", i2pKeys.Ed25519Seed)
	fmt.Printf("-----END I2P DESTINATION-----\n\n")
	return nil
}

// displayBeldexOutput derives and prints the 25-word Beldex seed (same Electrum encoding as Monero
// but with a "beldex" prefix for domain separation) and the primary address plus subaddresses.
func displayBeldexOutput(ed25519Key *ed25519.PrivateKey, seedPassphrase string) error {
	bdxSeed, bdxSeedErr := seedify.ToMoneroLegacySeedWithPrefix(ed25519Key, seedPassphrase, "beldex")
	if bdxSeedErr != nil {
		return fmt.Errorf("failed to derive Beldex seed: %w", bdxSeedErr)
	}

	fmt.Println("[25 word beldex (bdx) seed]")
	fmt.Println()
	fmt.Println(bdxSeed)
	fmt.Println()

	bdxKeys, bdxKErr := seedify.DeriveBeldexKeysFromLegacySeed(bdxSeed, 9) //nolint:mnd
	if bdxKErr != nil {
		return fmt.Errorf("failed to derive Beldex keys from legacy seed: %w", bdxKErr)
	}

	fmt.Println("[beldex addresses from 25 word seed]")
	fmt.Println()
	fmt.Printf("%s (primary address)\n", bdxKeys.PrimaryAddress)
	for j, subaddr := range bdxKeys.Subaddresses {
		fmt.Printf("> %s (subaddress 0,%d)\n", subaddr, j+1)
	}
	fmt.Println()
	return nil
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
	Cronos        string `json:"cronos"`
	Ethereum      string `json:"ethereum"`
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

// dnsRecordToNIP78Tags converts a dnsRecord to NIP-78 Kind 30078 compliant tags.
// Adds ["d", appID] first, then ["name", value] for each non-empty field.
func dnsRecordToNIP78Tags(record dnsRecord, appID string) [][]string {
	addTag := func(tags *[][]string, name, value string) {
		if value != "" {
			*tags = append(*tags, []string{name, value})
		}
	}
	tags := [][]string{{"d", appID}}
	addTag(&tags, "ssh-ed25519", record.SSHEd25519)
	addTag(&tags, "ssh-rsa", record.SSHRSA)
	addTag(&tags, "nostr", record.Nostr)
	addTag(&tags, "npub", record.Npub)
	addTag(&tags, "npubkey", record.NpubKey)
	addTag(&tags, "pubkey", record.PubKey)
	addTag(&tags, "hexpub", record.HexPub)
	addTag(&tags, "hexpubkey", record.HexPubKey)
	addTag(&tags, "bitcoin", record.Bitcoin)
	addTag(&tags, "silentpayment", record.SilentPayment)
	addTag(&tags, "paynym", record.PayNym)
	addTag(&tags, "litecoin", record.Litecoin)
	addTag(&tags, "dogecoin", record.Dogecoin)
	addTag(&tags, "monero", record.Monero)
	addTag(&tags, "cosmos", record.Cosmos)
	addTag(&tags, "noble", record.Noble)
	addTag(&tags, "arbitrum", record.Arbitrum)
	addTag(&tags, "avalanche", record.Avalanche)
	addTag(&tags, "base", record.Base)
	addTag(&tags, "bnbchain", record.BNBChain)
	addTag(&tags, "cronos", record.Cronos)
	addTag(&tags, "ethereum", record.Ethereum)
	addTag(&tags, "zcash", record.Zcash)
	addTag(&tags, "optimism", record.Optimism)
	addTag(&tags, "polygon", record.Polygon)
	addTag(&tags, "solana", record.Solana)
	addTag(&tags, "sui", record.Sui)
	addTag(&tags, "tron", record.Tron)
	addTag(&tags, "stellar", record.Stellar)
	addTag(&tags, "ripple", record.Ripple)
	return tags
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

	key, err := parsePrivateKey(bts, nil)
	if err != nil && isPasswordError(err) {
		pass, passErr := askKeyPassphrase(keyPath)
		if passErr != nil {
			return nil, nil, passErr
		}
		key, err = parsePrivateKey(bts, pass)
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

	nostrKeys, err := seedify.DeriveNostrKeysWithHex(mnemonic, "")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to derive Nostr keys: %w", err)
	}

	btcAddr, err := seedify.DeriveBitcoinAddressNativeSegwitAtIndex(mnemonic, "", 0)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to derive Bitcoin native SegWit address: %w", err)
	}

	sp1Addr, err := seedify.DeriveSilentPaymentAddress(mnemonic, "")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to derive Silent Payment (sp1) address: %w", err)
	}

	payNymKeys, err := seedify.DerivePayNym(mnemonic, "")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to derive PayNym: %w", err)
	}

	ltcAddr, err := seedify.DeriveLitecoinAddress(mnemonic, "")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to derive Litecoin address: %w", err)
	}

	dogeAddr, err := seedify.DeriveDogecoinAddress(mnemonic, "")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to derive Dogecoin address: %w", err)
	}

	dnsMonth, monthErr := getPolyseedMonth()
	if monthErr != nil {
		return nil, nil, fmt.Errorf("invalid --polyseed-month: %w", monthErr)
	}
	dnsYear, yearErr := getPolyseedYears()
	if yearErr != nil {
		return nil, nil, fmt.Errorf("invalid --polyseed-year: %w", yearErr)
	}
	polyseedMnemonic, err := seedify.ToMnemonicWithLength(ed25519Key, 16, seedPassphrase, false, birthdayFromYearMonth(dnsYear[0], dnsMonth)) //nolint:mnd
	if err != nil {
		return nil, nil, fmt.Errorf("could not generate 16-word polyseed: %w", err)
	}
	xmrAddr, err := seedify.DeriveMoneroAddress(polyseedMnemonic)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to derive Monero address: %w", err)
	}

	cosmosAddr, err := seedify.DeriveCosmosAddress(mnemonic, "")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to derive Cosmos address: %w", err)
	}

	nobleAddr, err := seedify.DeriveNobleAddress(mnemonic, "")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to derive Noble address: %w", err)
	}

	ethAddr, err := seedify.DeriveEthereumAddress(mnemonic, "")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to derive Ethereum address: %w", err)
	}

	zcashAddr, err := seedify.DeriveZcashAddress(mnemonic, "")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to derive Zcash address: %w", err)
	}

	solAddr, err := seedify.DeriveSolanaAddress(mnemonic, "")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to derive Solana address: %w", err)
	}

	suiAddr, err := seedify.DeriveSuiAddress(mnemonic, "")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to derive Sui address: %w", err)
	}

	tronAddr, err := seedify.DeriveTronAddress(mnemonic, "")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to derive Tron address: %w", err)
	}

	xlmAddr, err := seedify.DeriveStellarAddress(mnemonic, "")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to derive Stellar address: %w", err)
	}

	xrpAddr, err := seedify.DeriveRippleAddress(mnemonic, "")
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
		Cronos:        ethAddr,
		Ethereum:      ethAddr,
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

// publishDNSToRelays builds a NIP-78 Kind 30078 event from the dnsRecord and publishes it to the given relays.
func publishDNSToRelays(record *dnsRecord, nostrKeys *seedify.NostrKeys, relays []string) error {
	appID := zenprofileAppID
	if appID == "" {
		appID = "app.zenprofile.identifier"
	}
	tags := dnsRecordToNIP78Tags(*record, appID)
	const kindNIP78 = 30078
	ev := nostrpkg.Event{
		PubKey:    nostrKeys.PubKeyHex,
		CreatedAt: nostrpkg.Now(),
		Kind:      kindNIP78,
		Tags:      tagsToNostrTags(tags),
		Content:   "",
	}
	if err := ev.Sign(nostrKeys.PrivKeyHex); err != nil {
		return fmt.Errorf("failed to sign NIP-78 Kind 30078 event: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second) //nolint:mnd
	defer cancel()

	for _, url := range relays {
		relay, err := nostrpkg.RelayConnect(ctx, url)
		if err != nil {
			fmt.Fprintf(os.Stderr, "seedify: failed to connect to %s: %v\n", url, err)
			continue
		}
		if err := relay.Publish(ctx, ev); err != nil {
			fmt.Fprintf(os.Stderr, "seedify: failed to publish to %s: %v\n", url, err)
			continue
		}
		fmt.Fprintf(os.Stderr, "seedify: published NIP-78 Kind 30078 to %s\n", url)
	}
	return nil
}
