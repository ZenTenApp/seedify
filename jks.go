package seedify

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"strings"
	"time"

	keystore "github.com/pavlo-v-chernykh/keystore-go/v4"
)

// DefaultJKSValidityDays is the default self-signed certificate validity for JKS export.
const DefaultJKSValidityDays = 10000

// JKSKeypair holds deterministic RSA key material and a self-signed X.509
// certificate suitable for export as a Java KeyStore entry.
type JKSKeypair struct {
	// Alias is the keystore entry alias.
	Alias string

	// PrivateKey is the derived RSA private key.
	PrivateKey *rsa.PrivateKey

	// PrivateKeyPKCS8 is the PKCS#8 DER encoding of PrivateKey.
	PrivateKeyPKCS8 []byte

	// CertificateDER is the DER-encoded self-signed X.509 certificate.
	CertificateDER []byte

	// DistinguishedName is the certificate subject and issuer.
	DistinguishedName pkix.Name

	// NotBefore is the certificate validity start time.
	NotBefore time.Time

	// NotAfter is the certificate validity end time.
	NotAfter time.Time

	// SerialNumber is the certificate serial number.
	SerialNumber *big.Int

	// CreationTime is the fixed JKS entry creation timestamp.
	CreationTime time.Time

	saltSeed [32]byte
}

// DeriveJKSKeypair deterministically derives an RSA private key and self-signed
// X.509 certificate from an Ed25519 private key for Java/Android JKS export.
//
// alias is the keystore entry alias and is included in the domain-separation
// label so different aliases produce distinct keys from the same source key.
// bits must be 2048, 3072, or 4096. validityDays must be at least 1.
//
// When dn is empty, the distinguished name defaults to CN=<alias>.
func DeriveJKSKeypair(key *ed25519.PrivateKey, alias string, bits int, validityDays int, dn pkix.Name) (*JKSKeypair, error) {
	if alias == "" {
		return nil, fmt.Errorf("JKS alias cannot be empty")
	}
	if validityDays < 1 {
		return nil, fmt.Errorf("JKS validity must be at least 1 day, got %d", validityDays)
	}

	subject := dn
	if distinguishedNameEmpty(subject) {
		subject.CommonName = alias
	}

	label := []byte(fmt.Sprintf("seedify:jks:%s:%d:", alias, bits))
	input := make([]byte, len(label)+len(key.Seed()))
	copy(input, label)
	copy(input[len(label):], key.Seed())
	domainHash := sha256.Sum256(input)

	rsaKey, err := deriveRSAKeyFromDomainHash(domainHash, bits)
	if err != nil {
		return nil, fmt.Errorf("could not derive RSA key for JKS: %w", err)
	}

	privDER, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		return nil, fmt.Errorf("could not marshal JKS private key to PKCS#8: %w", err)
	}

	notBefore := pgpEpoch
	notAfter := notBefore.AddDate(0, 0, validityDays)
	serial := serialNumberFromDomainHash(domainHash)

	template := x509.Certificate{
		SerialNumber:          serial,
		Subject:               subject,
		Issuer:                subject,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		BasicConstraintsValid: true,
	}

	certRand, err := newDeterministicReader(domainHash[:])
	if err != nil {
		return nil, fmt.Errorf("could not create certificate signer: %w", err)
	}

	certDER, err := x509.CreateCertificate(certRand, &template, &template, &rsaKey.PublicKey, rsaKey)
	if err != nil {
		return nil, fmt.Errorf("could not create JKS certificate: %w", err)
	}

	saltLabel := []byte(fmt.Sprintf("seedify:jks-salt:%s:", alias))
	saltInput := make([]byte, len(saltLabel)+len(key.Seed()))
	copy(saltInput, saltLabel)
	copy(saltInput[len(saltLabel):], key.Seed())

	return &JKSKeypair{
		Alias:             alias,
		PrivateKey:        rsaKey,
		PrivateKeyPKCS8:   privDER,
		CertificateDER:    certDER,
		DistinguishedName: subject,
		NotBefore:         notBefore,
		NotAfter:          notAfter,
		SerialNumber:      serial,
		CreationTime:      pgpEpoch,
		saltSeed:          sha256.Sum256(saltInput),
	}, nil
}

// EncodeJKS writes the keypair as a password-protected Java KeyStore (JKS) file.
func EncodeJKS(pair *JKSKeypair, password []byte) ([]byte, error) {
	if pair == nil {
		return nil, fmt.Errorf("JKS keypair cannot be nil")
	}
	if len(password) == 0 {
		return nil, fmt.Errorf("JKS keystore password cannot be empty")
	}

	saltRand, err := newDeterministicReader(pair.saltSeed[:])
	if err != nil {
		return nil, fmt.Errorf("could not create JKS salt generator: %w", err)
	}

	ks := keystore.New(
		keystore.WithCustomRandomNumberGenerator(saltRand),
		keystore.WithCaseExactAliases(),
	)

	entry := keystore.PrivateKeyEntry{
		CreationTime: pair.CreationTime,
		PrivateKey:   pair.PrivateKeyPKCS8,
		CertificateChain: []keystore.Certificate{{
			Type:    "X509",
			Content: pair.CertificateDER,
		}},
	}

	if err := ks.SetPrivateKeyEntry(pair.Alias, entry, password); err != nil {
		return nil, fmt.Errorf("could not add JKS private key entry: %w", err)
	}

	var buf bytes.Buffer
	if err := ks.Store(&buf, password); err != nil {
		return nil, fmt.Errorf("could not encode JKS: %w", err)
	}

	return buf.Bytes(), nil
}

// ParseJKSDistinguishedName parses a comma-separated distinguished name string
// into a pkix.Name. Supported attributes are CN, OU, O, L, ST, and C.
func ParseJKSDistinguishedName(dn string) (pkix.Name, error) {
	dn = strings.TrimSpace(dn)
	if dn == "" {
		return pkix.Name{}, fmt.Errorf("JKS distinguished name cannot be empty")
	}

	name := pkix.Name{}
	parts := strings.Split(dn, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			return pkix.Name{}, fmt.Errorf("JKS distinguished name contains an empty component")
		}

		key, value, ok := strings.Cut(part, "=")
		if !ok {
			return pkix.Name{}, fmt.Errorf("invalid JKS distinguished name component %q: expected KEY=VALUE", part)
		}

		key = strings.ToUpper(strings.TrimSpace(key))
		value = strings.TrimSpace(value)
		if value == "" {
			return pkix.Name{}, fmt.Errorf("invalid JKS distinguished name component %q: value cannot be empty", part)
		}

		switch key {
		case "CN":
			name.CommonName = value
		case "OU":
			name.OrganizationalUnit = append(name.OrganizationalUnit, value)
		case "O":
			name.Organization = append(name.Organization, value)
		case "L":
			name.Locality = []string{value}
		case "ST":
			name.Province = []string{value}
		case "C":
			name.Country = []string{value}
		default:
			return pkix.Name{}, fmt.Errorf("unsupported JKS distinguished name attribute %q", key)
		}
	}

	if distinguishedNameEmpty(name) {
		return pkix.Name{}, fmt.Errorf("JKS distinguished name must include at least one supported attribute")
	}

	return name, nil
}

func distinguishedNameEmpty(name pkix.Name) bool {
	return name.CommonName == "" &&
		len(name.Organization) == 0 &&
		len(name.OrganizationalUnit) == 0 &&
		len(name.Locality) == 0 &&
		len(name.Province) == 0 &&
		len(name.Country) == 0
}

func serialNumberFromDomainHash(domainHash [32]byte) *big.Int {
	serial := new(big.Int).SetBytes(domainHash[:])
	maxSerial := new(big.Int).Lsh(big.NewInt(1), 159) //nolint:mnd
	serial.Mod(serial, maxSerial)
	if serial.Sign() <= 0 {
		serial.SetInt64(1)
	}
	return serial
}
