package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"

	"golang.org/x/crypto/blowfish"
	"golang.org/x/crypto/ssh"
)

const (
	openSSHPrivateKeyAuthMagic        = "openssh-key-v1\x00"
	defaultOpenSSHBcryptKDFRounds     = 16
	bcryptPBKDFBlockSize              = 32
	openSSHPrivateKeyBcryptSaltLength = 16
)

type openSSHEncryptedPrivateKeyWithKDF struct {
	CipherName   string
	KdfName      string
	KdfOpts      string
	NumKeys      uint32
	PubKey       []byte
	PrivKeyBlock []byte
}

type openSSHPrivateKeyWithKDF struct {
	Check1  uint32
	Check2  uint32
	Keytype string
	Rest    []byte `ssh:"rest"`
}

type openSSHEd25519PrivateKeyWithKDF struct {
	Pub     []byte
	Priv    []byte
	Comment string
	Pad     []byte `ssh:"rest"`
}

// marshalOpenSSHEd25519PrivateKeyWithPassphraseKDFRounds serializes an Ed25519
// key in OpenSSH private-key format, encrypting it with aes256-ctr and bcrypt
// KDF using the requested round count. x/crypto/ssh's public helper hardcodes
// the round count, so seedify uses this narrowly-scoped marshaller for
// --secret-bunker-kdf-rounds.
func marshalOpenSSHEd25519PrivateKeyWithPassphraseKDFRounds(key ed25519.PrivateKey, comment string, passphrase []byte, rounds int) (*pem.Block, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("ssh: ed25519 private key unexpected length %d", len(key))
	}
	if rounds < 1 {
		return nil, errors.New("ssh: bcrypt KDF rounds must be at least 1")
	}

	var check uint32
	if err := binary.Read(rand.Reader, binary.BigEndian, &check); err != nil {
		return nil, err
	}

	pub := make([]byte, ed25519.PublicKeySize)
	priv := make([]byte, ed25519.PrivateKeySize)
	copy(pub, key[ed25519.SeedSize:])
	copy(priv, key)

	pubKey := struct {
		KeyType string
		Pub     []byte
	}{
		KeyType: ssh.KeyAlgoED25519,
		Pub:     pub,
	}

	edKey := openSSHEd25519PrivateKeyWithKDF{
		Pub:     pub,
		Priv:    priv,
		Comment: comment,
	}

	pk := openSSHPrivateKeyWithKDF{
		Check1:  check,
		Check2:  check,
		Keytype: ssh.KeyAlgoED25519,
		Rest:    ssh.Marshal(edKey),
	}

	protected, kdfOptions, err := encryptOpenSSHPrivateKeyBlockWithBcryptRounds(ssh.Marshal(pk), passphrase, rounds)
	if err != nil {
		return nil, err
	}

	wrapped := openSSHEncryptedPrivateKeyWithKDF{
		CipherName:   "aes256-ctr",
		KdfName:      "bcrypt",
		KdfOpts:      string(kdfOptions),
		NumKeys:      1,
		PubKey:       ssh.Marshal(pubKey),
		PrivKeyBlock: protected,
	}

	return &pem.Block{
		Type:  "OPENSSH PRIVATE KEY",
		Bytes: append([]byte(openSSHPrivateKeyAuthMagic), ssh.Marshal(wrapped)...),
	}, nil
}

func encryptOpenSSHPrivateKeyBlockWithBcryptRounds(privKeyBlock, passphrase []byte, rounds int) ([]byte, []byte, error) {
	salt := make([]byte, openSSHPrivateKeyBcryptSaltLength)
	if _, err := rand.Read(salt); err != nil {
		return nil, nil, err
	}

	opts := struct {
		Salt   []byte
		Rounds uint32
	}{
		Salt:   salt,
		Rounds: uint32(rounds), //nolint:gosec // rounds is validated positive; practical values fit uint32.
	}

	k, err := bcryptPBKDFKey(passphrase, salt, int(opts.Rounds), 32+aes.BlockSize)
	if err != nil {
		return nil, nil, err
	}

	keyBlock := generateOpenSSHPaddingForKDF(privKeyBlock, aes.BlockSize)
	dst := make([]byte, len(keyBlock))
	key, iv := k[:32], k[32:]
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(dst, keyBlock)

	return dst, ssh.Marshal(opts), nil
}

func generateOpenSSHPaddingForKDF(block []byte, blockSize int) []byte {
	for i, l := 0, len(block); (l+i)%blockSize != 0; i++ {
		block = append(block, byte(i+1))
	}
	return block
}

// bcryptPBKDFKey implements OpenBSD bcrypt_pbkdf(3), the KDF OpenSSH uses for
// encrypted private keys. It is adapted from golang.org/x/crypto/ssh/internal/
// bcrypt_pbkdf, which cannot be imported outside x/crypto/ssh/internal.
func bcryptPBKDFKey(password, salt []byte, rounds, keyLen int) ([]byte, error) {
	if rounds < 1 {
		return nil, errors.New("bcrypt_pbkdf: number of rounds is too small")
	}
	if len(password) == 0 {
		return nil, errors.New("bcrypt_pbkdf: empty password")
	}
	if len(salt) == 0 || len(salt) > 1<<20 {
		return nil, errors.New("bcrypt_pbkdf: bad salt length")
	}
	if keyLen > 1024 {
		return nil, errors.New("bcrypt_pbkdf: keyLen is too large")
	}

	numBlocks := (keyLen + bcryptPBKDFBlockSize - 1) / bcryptPBKDFBlockSize
	key := make([]byte, numBlocks*bcryptPBKDFBlockSize)

	h := sha512.New()
	h.Write(password) //nolint:errcheck // hash.Hash Write never returns an error.
	shapass := h.Sum(nil)

	shasalt := make([]byte, 0, sha512.Size)
	cnt, tmp := make([]byte, 4), make([]byte, bcryptPBKDFBlockSize)
	for block := 1; block <= numBlocks; block++ {
		h.Reset()
		h.Write(salt) //nolint:errcheck // hash.Hash Write never returns an error.
		cnt[0] = byte(block >> 24)
		cnt[1] = byte(block >> 16)
		cnt[2] = byte(block >> 8)
		cnt[3] = byte(block)
		h.Write(cnt) //nolint:errcheck // hash.Hash Write never returns an error.
		bcryptPBKDFHash(tmp, shapass, h.Sum(shasalt))

		out := make([]byte, bcryptPBKDFBlockSize)
		copy(out, tmp)
		for i := 2; i <= rounds; i++ {
			h.Reset()
			h.Write(tmp) //nolint:errcheck // hash.Hash Write never returns an error.
			bcryptPBKDFHash(tmp, shapass, h.Sum(shasalt))
			for j := range out {
				out[j] ^= tmp[j]
			}
		}

		for i, v := range out {
			key[i*numBlocks+(block-1)] = v
		}
	}
	return key[:keyLen], nil
}

var bcryptPBKDFMagic = []byte("OxychromaticBlowfishSwatDynamite")

func bcryptPBKDFHash(out, shapass, shasalt []byte) {
	c, err := blowfish.NewSaltedCipher(shapass, shasalt)
	if err != nil {
		panic(err)
	}
	for i := 0; i < 64; i++ {
		blowfish.ExpandKey(shasalt, c)
		blowfish.ExpandKey(shapass, c)
	}
	copy(out, bcryptPBKDFMagic)
	for i := 0; i < bcryptPBKDFBlockSize; i += 8 {
		for j := 0; j < 64; j++ {
			c.Encrypt(out[i:i+8], out[i:i+8])
		}
	}
	// Swap bytes due to different endianness.
	for i := 0; i < bcryptPBKDFBlockSize; i += 4 {
		out[i+3], out[i+2], out[i+1], out[i] = out[i], out[i+1], out[i+2], out[i+3]
	}
}
