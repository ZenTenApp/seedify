package main

import (
	"fmt"
	"os"
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
	color := isatty.IsTerminal(os.Stdout.Fd()) && os.Getenv("NO_COLOR") == ""
	o := &cliOut{color: color}
	if !color {
		return o
	}

	white := lipgloss.Color(completeColor("#FFFFFF", "15", "15"))
	public := lipgloss.Color(completeColor("#7CFC00", "118", "10"))
	private := lipgloss.Color(completeColor("#FF0000", "196", "1"))

	o.sectionStyle = lipgloss.NewStyle().Bold(true).Foreground(white)
	o.labelStyle = lipgloss.NewStyle().Foreground(white)
	o.valueStyle = lipgloss.NewStyle().Foreground(public)
	o.sensitiveStyle = lipgloss.NewStyle().Foreground(private)
	o.borderStyle = lipgloss.NewStyle().Foreground(white)
	o.treeStyle = lipgloss.NewStyle().Foreground(white)
	return o
}


const (
	sectionGapLines  = 2
	dividerRuleWidth = 40
)

var out = newCLIOut()

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
	begin := "-----BEGIN " + label + "-----"
	end := "-----END " + label + "-----"
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
