package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/mattn/go-isatty"
	"github.com/muesli/termenv"
)

// cliOut formats seedify's human-readable stdout with optional terminal styling.
// Styling is enabled only when stdout is a TTY and NO_COLOR is unset.
type cliOut struct {
	color          bool
	sectionStyle   lipgloss.Style
	labelStyle     lipgloss.Style
	valueStyle     lipgloss.Style
	sensitiveStyle lipgloss.Style
	borderStyle    lipgloss.Style
	treeStyle      lipgloss.Style
}

func newCLIOut() *cliOut {
	o, _ := newCLIOutWithConfig("")
	return o
}

func newCLIOutWithConfig(path string) (*cliOut, error) {
	color := isatty.IsTerminal(os.Stdout.Fd()) && os.Getenv("NO_COLOR") == ""
	o := &cliOut{color: color}
	if !color {
		return o, nil
	}

	palette := terminalPalette()
	if path != "" {
		var err error
		palette, err = applyINIColorOverrides(palette, path)
		if err != nil {
			return nil, err
		}
	}

	o.sectionStyle = lipgloss.NewStyle().Bold(true).Foreground(palette.text)
	o.labelStyle = lipgloss.NewStyle().Foreground(palette.text)
	o.valueStyle = lipgloss.NewStyle().Foreground(palette.public)
	o.sensitiveStyle = lipgloss.NewStyle().Foreground(palette.private)
	o.borderStyle = lipgloss.NewStyle().Foreground(palette.text)
	o.treeStyle = lipgloss.NewStyle().Foreground(palette.text)
	return o, nil
}

const (
	sectionGapLines  = 2
	dividerRuleWidth = 40
)

var out = newCLIOut()

type cliPalette struct {
	text    lipgloss.Color
	public  lipgloss.Color
	private lipgloss.Color
}

func terminalPalette() cliPalette {
	if terminalHasDarkBackground() {
		return cliPalette{
			text:    lipgloss.Color(completeColor("#FFFFFF", "15", "15")),
			public:  lipgloss.Color(completeColor("#7CFC00", "118", "10")),
			private: lipgloss.Color(completeColor("#FF5555", "203", "9")),
		}
	}
	return cliPalette{
		text:    lipgloss.Color(completeColor("#111111", "233", "0")),
		public:  lipgloss.Color(completeColor("#006B00", "22", "2")),
		private: lipgloss.Color(completeColor("#B00020", "124", "1")),
	}
}

func terminalHasDarkBackground() bool {
	if !isatty.IsTerminal(os.Stdout.Fd()) {
		return true
	}
	return termenv.HasDarkBackground()
}

func configureCLIOutput(configExplicit bool) error {
	path := strings.TrimSpace(configPath)
	if path == "" {
		out = newCLIOut()
		return nil
	}

	expanded, err := expandPath(path)
	if err != nil {
		return err
	}

	if !configExplicit {
		if _, statErr := os.Stat(expanded); errorsIsNotExist(statErr) {
			out = newCLIOut()
			return nil
		}
	}

	configuredOut, err := newCLIOutWithConfig(expanded)
	if err != nil {
		return err
	}
	out = configuredOut
	return nil
}

func expandPath(path string) (string, error) {
	if path == "~" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("could not resolve home directory: %w", err)
		}
		return home, nil
	}
	if strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("could not resolve home directory: %w", err)
		}
		return filepath.Join(home, strings.TrimPrefix(path, "~/")), nil
	}
	return path, nil
}

func errorsIsNotExist(err error) bool {
	return err != nil && os.IsNotExist(err)
}

var hexColorPattern = regexp.MustCompile(`^#[0-9a-fA-F]{6}$`)

func applyINIColorOverrides(palette cliPalette, path string) (cliPalette, error) {
	colors, err := readINIColors(path)
	if err != nil {
		return palette, err
	}
	for key, value := range colors {
		color, colorErr := parseConfigColor(value)
		if colorErr != nil {
			return palette, fmt.Errorf("invalid color for colors.%s: %w", key, colorErr)
		}
		switch key {
		case "labels":
			palette.text = color
		case "public":
			palette.public = color
		case "private":
			palette.private = color
		}
	}
	return palette, nil
}

func readINIColors(path string) (map[string]string, error) {
	f, err := os.Open(path) //nolint:gosec // User-configurable CLI config path.
	if err != nil {
		return nil, fmt.Errorf("could not read config %s: %w", path, err)
	}
	defer f.Close() //nolint:errcheck

	colors := map[string]string{}
	section := ""
	scanner := bufio.NewScanner(f)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(line, "["), "]")))
			continue
		}
		if section != "colors" {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("invalid config %s:%d: expected key = value", path, lineNo)
		}
		key = strings.ToLower(strings.TrimSpace(key))
		if key != "labels" && key != "public" && key != "private" {
			continue
		}
		colors[key] = strings.Trim(strings.TrimSpace(value), `"'`)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("could not read config %s: %w", path, err)
	}
	return colors, nil
}

func parseConfigColor(value string) (lipgloss.Color, error) {
	if hexColorPattern.MatchString(value) {
		return lipgloss.Color(value), nil
	}
	n, err := strconv.Atoi(value)
	if err == nil && n >= 0 && n <= 255 {
		return lipgloss.Color(value), nil
	}
	return "", fmt.Errorf("%q; expected #RRGGBB or ANSI color number 0-255", value)
}

// completeColor picks the best color string for the active terminal profile.
// Lipgloss resolves colors differently per capability: 24-bit hex on true-color
// terminals, palette indices on 256-color terminals, and basic ANSI codes
// (e.g. "2" for green) as the fallback.
func completeColor(truecolor, ansi256, ansi string) string {
	//nolint:exhaustive
	switch lipgloss.ColorProfile() {
	case termenv.TrueColor:
		return truecolor
	case termenv.ANSI256:
		return ansi256
	}
	return ansi
}

func (o *cliOut) render(style lipgloss.Style, s string) string {
	if !o.color {
		return s
	}
	return style.Render(s)
}

// Section prints a [title] header.
func (o *cliOut) Section(title string) {
	fmt.Println(o.render(o.sectionStyle, "["+title+"]"))
}

// Sectionf prints a formatted [title] header.
func (o *cliOut) Sectionf(format string, args ...any) {
	o.Section(fmt.Sprintf(format, args...))
}

// Blank prints an empty line.
func (o *cliOut) Blank() {
	fmt.Println()
}

// Blanks prints n empty lines.
func (o *cliOut) Blanks(n int) {
	for range n {
		fmt.Println()
	}
}

// SectionGap prints the standard vertical spacing between major CLI sections.
func (o *cliOut) SectionGap() {
	o.Blanks(sectionGapLines)
}

// Sensitive prints secret material such as mnemonics and private keys.
func (o *cliOut) Sensitive(s string) {
	fmt.Println(o.render(o.sensitiveStyle, s))
}

// Value prints a non-secret datum such as addresses and public keys.
func (o *cliOut) Value(s string) {
	fmt.Println(o.render(o.valueStyle, s))
}

// Field prints "value (description)".
func (o *cliOut) Field(value, description string) {
	if !o.color {
		fmt.Printf("%s (%s)\n", value, description)
		return
	}
	fmt.Printf("%s %s\n",
		o.valueStyle.Render(value),
		o.labelStyle.Render("("+description+")"),
	)
}

// SensitiveField prints secret material with a trailing description.
func (o *cliOut) SensitiveField(value, description string) {
	if !o.color {
		fmt.Printf("%s (%s)\n", value, description)
		return
	}
	fmt.Printf("%s %s\n",
		o.sensitiveStyle.Render(value),
		o.labelStyle.Render("("+description+")"),
	)
}

// TreeField prints "└─ value (description)".
func (o *cliOut) TreeField(value, description string) {
	const branch = "└─"
	if !o.color {
		fmt.Printf("%s %s (%s)\n", branch, value, description)
		return
	}
	fmt.Printf("%s %s %s\n",
		o.treeStyle.Render(branch),
		o.valueStyle.Render(value),
		o.labelStyle.Render("("+description+")"),
	)
}

// SensitiveTreeField prints "└─ secret (description)".
func (o *cliOut) SensitiveTreeField(value, description string) {
	const branch = "└─"
	if !o.color {
		fmt.Printf("%s %s (%s)\n", branch, value, description)
		return
	}
	fmt.Printf("%s %s %s\n",
		o.treeStyle.Render(branch),
		o.sensitiveStyle.Render(value),
		o.labelStyle.Render("("+description+")"),
	)
}

// SubField prints "> value (description)" for nested items such as subaddresses.
func (o *cliOut) SubField(value, description string) {
	const prefix = ">"
	if !o.color {
		fmt.Printf("%s %s (%s)\n", prefix, value, description)
		return
	}
	fmt.Printf("%s %s %s\n",
		o.treeStyle.Render(prefix),
		o.valueStyle.Render(value),
		o.labelStyle.Render("("+description+")"),
	)
}

// SeedSection prints a mnemonic block with a section header.
func (o *cliOut) SeedSection(title, mnemonic string) {
	o.Section(title)
	o.Blank()
	o.Sensitive(mnemonic)
	o.Blank()
}

// AddressSection prints a single address under a section header.
func (o *cliOut) AddressSection(title, addr string) {
	o.Section(title)
	o.Blank()
	o.Value(addr)
	o.Blank()
}

// PEMBlock prints BEGIN/content/END markers. Set sensitive for secret content.
func (o *cliOut) PEMBlock(label, content string, sensitive bool) {
	o.PEMBlockDelimited(label, content, "-----", sensitive)
}

// PEMBlockDelimited prints BEGIN/content/END markers with a custom delimiter.
func (o *cliOut) PEMBlockDelimited(label, content, delimiter string, sensitive bool) {
	begin := delimiter + "BEGIN " + label + delimiter
	end := delimiter + "END " + label + delimiter
	if !o.color {
		fmt.Printf("%s\n%s\n%s\n", begin, content, end)
		return
	}
	contentStyle := o.valueStyle
	if sensitive {
		contentStyle = o.sensitiveStyle
	}
	fmt.Println(o.borderStyle.Render(begin))
	fmt.Println(contentStyle.Render(content))
	fmt.Println(o.borderStyle.Render(end))
}

// PEMBlockPrefixed prints leading blank lines then a PEM block.
func (o *cliOut) PEMBlockPrefixed(leadingBlanks int, label, content string, sensitive bool) {
	o.Blanks(leadingBlanks)
	o.PEMBlock(label, content, sensitive)
}

// LabeledBlock prints a bordered block with multiple labeled lines inside.
func (o *cliOut) LabeledBlock(label string, lines []string) {
	begin := "-----BEGIN " + label + "-----"
	end := "-----END " + label + "-----"
	if !o.color {
		fmt.Println(begin)
		for _, line := range lines {
			fmt.Println(line)
		}
		fmt.Println(end)
		return
	}
	fmt.Println(o.borderStyle.Render(begin))
	for _, line := range lines {
		fmt.Println(o.valueStyle.Render(line))
	}
	fmt.Println(o.borderStyle.Render(end))
}

// NostrKeyBlock prints the four-line Nostr key export used by --phrases output.
func (o *cliOut) NostrKeyBlock(npub, pubHex, nsec, privHex string) {
	border := "----- nPubKey / hexPubKey / nSecKey / hexSecKey -----"
	if !o.color {
		fmt.Println(border)
		fmt.Println(npub)
		fmt.Println(pubHex)
		fmt.Println(nsec)
		fmt.Println(privHex)
		fmt.Println(border)
		return
	}
	fmt.Println(o.borderStyle.Render(border))
	fmt.Println(o.valueStyle.Render(npub))
	fmt.Println(o.valueStyle.Render(pubHex))
	fmt.Println(o.sensitiveStyle.Render(nsec))
	fmt.Println(o.sensitiveStyle.Render(privHex))
	fmt.Println(o.borderStyle.Render(border))
}

// Divider prints a subtle horizontal rule between major sections.
func (o *cliOut) Divider() {
	if !o.color {
		return
	}
	rule := strings.Repeat("─", dividerRuleWidth)
	fmt.Println(o.borderStyle.Render(rule))
}
