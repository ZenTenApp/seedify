package seedify

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"

	keystore "github.com/pavlo-v-chernykh/keystore-go/v4"
)

func testEd25519Key(t *testing.T, seed byte) ed25519.PrivateKey {
	t.Helper()

	seedBytes := make([]byte, ed25519.SeedSize)
	for i := range seedBytes {
		seedBytes[i] = seed + byte(i)
	}

	return ed25519.NewKeyFromSeed(seedBytes)
}

func TestDeriveJKSKeypairDeterministic(t *testing.T) {
	key := testEd25519Key(t, 7)

	first, err := DeriveJKSKeypair(&key, "zenten", 2048, DefaultJKSValidityDays, pkixName("CN=Zenten"))
	if err != nil {
		t.Fatalf("derive first JKS keypair: %v", err)
	}

	second, err := DeriveJKSKeypair(&key, "zenten", 2048, DefaultJKSValidityDays, pkixName("CN=Zenten"))
	if err != nil {
		t.Fatalf("derive second JKS keypair: %v", err)
	}

	if !bytes.Equal(first.PrivateKeyPKCS8, second.PrivateKeyPKCS8) {
		t.Fatalf("PKCS#8 private keys differ")
	}
	if !bytes.Equal(first.CertificateDER, second.CertificateDER) {
		t.Fatalf("certificates differ")
	}
}

func TestDeriveJKSKeypairDifferentAlias(t *testing.T) {
	key := testEd25519Key(t, 11)

	first, err := DeriveJKSKeypair(&key, "zenten", 2048, DefaultJKSValidityDays, pkix.Name{})
	if err != nil {
		t.Fatalf("derive first JKS keypair: %v", err)
	}

	second, err := DeriveJKSKeypair(&key, "other", 2048, DefaultJKSValidityDays, pkix.Name{})
	if err != nil {
		t.Fatalf("derive second JKS keypair: %v", err)
	}

	if first.PrivateKey.N.Cmp(second.PrivateKey.N) == 0 {
		t.Fatalf("different aliases produced identical RSA keys")
	}
}

func TestDeriveJKSKeypairDefaultsCommonName(t *testing.T) {
	key := testEd25519Key(t, 3)

	pair, err := DeriveJKSKeypair(&key, "zenten", 2048, DefaultJKSValidityDays, pkix.Name{})
	if err != nil {
		t.Fatalf("derive JKS keypair: %v", err)
	}

	if pair.DistinguishedName.CommonName != "zenten" {
		t.Fatalf("common name = %q, want %q", pair.DistinguishedName.CommonName, "zenten")
	}
}

func TestParseJKSDistinguishedName(t *testing.T) {
	name, err := ParseJKSDistinguishedName("CN=Zenten, OU=Mobile, O=ZenTen, L=City, ST=State, C=US")
	if err != nil {
		t.Fatalf("parse distinguished name: %v", err)
	}

	if name.CommonName != "Zenten" {
		t.Fatalf("common name = %q, want Zenten", name.CommonName)
	}
	if len(name.OrganizationalUnit) != 1 || name.OrganizationalUnit[0] != "Mobile" {
		t.Fatalf("organizational unit = %#v, want [Mobile]", name.OrganizationalUnit)
	}
	if len(name.Organization) != 1 || name.Organization[0] != "ZenTen" {
		t.Fatalf("organization = %#v, want [ZenTen]", name.Organization)
	}
	if len(name.Locality) != 1 || name.Locality[0] != "City" {
		t.Fatalf("locality = %#v, want [City]", name.Locality)
	}
	if len(name.Province) != 1 || name.Province[0] != "State" {
		t.Fatalf("province = %#v, want [State]", name.Province)
	}
	if len(name.Country) != 1 || name.Country[0] != "US" {
		t.Fatalf("country = %#v, want [US]", name.Country)
	}
}

func TestEncodeJKSRoundTrip(t *testing.T) {
	key := testEd25519Key(t, 19)
	pair, err := DeriveJKSKeypair(&key, "zenten", 2048, DefaultJKSValidityDays, pkixName("CN=Zenten"))
	if err != nil {
		t.Fatalf("derive JKS keypair: %v", err)
	}

	password := []byte("changeit")
	first, err := EncodeJKS(pair, password)
	if err != nil {
		t.Fatalf("encode first JKS: %v", err)
	}

	second, err := EncodeJKS(pair, password)
	if err != nil {
		t.Fatalf("encode second JKS: %v", err)
	}

	if !bytes.Equal(first, second) {
		t.Fatalf("encoded JKS bytes differ for identical inputs")
	}

	ks := keystore.New(keystore.WithCaseExactAliases())
	if err := ks.Load(bytes.NewReader(first), password); err != nil {
		t.Fatalf("load JKS: %v", err)
	}

	if !ks.IsPrivateKeyEntry("zenten") {
		t.Fatalf("keystore does not contain alias zenten")
	}

	entry, err := ks.GetPrivateKeyEntry("zenten", password)
	if err != nil {
		t.Fatalf("get private key entry: %v", err)
	}

	if !bytes.Equal(entry.PrivateKey, pair.PrivateKeyPKCS8) {
		t.Fatalf("decoded private key does not match")
	}

	if len(entry.CertificateChain) != 1 {
		t.Fatalf("certificate chain length = %d, want 1", len(entry.CertificateChain))
	}

	cert, err := x509.ParseCertificate(entry.CertificateChain[0].Content)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}

	if cert.Subject.CommonName != "Zenten" {
		t.Fatalf("certificate CN = %q, want Zenten", cert.Subject.CommonName)
	}
	if cert.NotAfter.Sub(pair.NotAfter) != 0 {
		t.Fatalf("certificate NotAfter = %v, want %v", cert.NotAfter, pair.NotAfter)
	}
}

func pkixName(dn string) pkix.Name {
	name, err := ParseJKSDistinguishedName(dn)
	if err != nil {
		panic(err)
	}
	return name
}
