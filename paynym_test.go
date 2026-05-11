// Copyright (c) 2025-2026 complex (complex@ft.hn)
// See LICENSE for licensing information

package seedify

import (
	"testing"

	"github.com/matryer/is"
)

// TestDerivePayNym_BIP47TestVector verifies PayNym derivation against BIP47 test vectors.
// See: https://gist.github.com/SamouraiDev/6aad669604c5930864bd
func TestDerivePayNym_BIP47TestVector(t *testing.T) {
	is := is.New(t)

	// Alice's wallet from BIP47 test vectors
	aliceMnemonic := "response seminar brave tip suit recall often sound stick owner lottery motion"
	payNym, err := DerivePayNym(aliceMnemonic, "")
	is.NoErr(err)
	is.True(payNym != nil)

	// Expected payment code from test vectors
	expectedPaymentCode := "PM8TJTLJbPRGxSbc8EJi42Wrr6QbNSaSSVJ5Y3E4pbCYiTHUskHg13935Ubb7q8tx9GVbh2UuRnBc3WSyJHhUrw8KhprKnn9eDznYGieTzFcwQRya4GA"
	is.Equal(payNym.PaymentCode, expectedPaymentCode)

	// Expected notification address from test vectors
	expectedNotificationAddr := "1JDdmqFLhpzcUwPeinhJbUPw4Co3aWLyzW"
	is.Equal(payNym.NotificationAddress, expectedNotificationAddr)
}

// TestDerivePayNym_BobTestVector verifies Bob's PayNym from BIP47 test vectors.
func TestDerivePayNym_BobTestVector(t *testing.T) {
	is := is.New(t)

	bobMnemonic := "reward upper indicate eight swift arch injury crystal super wrestle already dentist"
	payNym, err := DerivePayNym(bobMnemonic, "")
	is.NoErr(err)
	is.True(payNym != nil)

	expectedPaymentCode := "PM8TJS2JxQ5ztXUpBBRnpTbcUXbUHy2T1abfrb3KkAAtMEGNbey4oumH7Hc578WgQJhPjBxteQ5GHHToTYHE3A1w6p7tU6KSoFmWBVbFGjKPisZDbP97"
	is.Equal(payNym.PaymentCode, expectedPaymentCode)

	expectedNotificationAddr := "1ChvUUvht2hUQufHBXF8NgLhW8SwE2ecGV"
	is.Equal(payNym.NotificationAddress, expectedNotificationAddr)
}

// TestDerivePayNym_Format validates payment code and notification address format.
func TestDerivePayNym_Format(t *testing.T) {
	is := is.New(t)

	mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	payNym, err := DerivePayNym(mnemonic, "")
	is.NoErr(err)
	is.True(payNym != nil)

	// Payment code should start with "PM8T" (Base58Check with version 0x47)
	is.True(len(payNym.PaymentCode) >= 4)
	is.Equal(payNym.PaymentCode[:4], "PM8T")

	// Notification address should start with "1" (Bitcoin mainnet P2PKH)
	is.True(len(payNym.NotificationAddress) >= 1)
	is.Equal(payNym.NotificationAddress[:1], "1")
}
