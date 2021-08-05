package pubkey

/*
 * Copyright 2015 Google Inc. All Rights Reserved.
 * Copyright 2021 kloeckner.i GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

import "crypto/md5" // #nosec

// ErrInvalidPEM is returned when a malformed certificate is provided.
var ErrInvalidPEM = errors.New("invalid pem")

// ParseCertificate decodes a PEM encoded certificate.
func ParseCertificate(certPEM string) (*x509.Certificate, error) {
	bl, _ := pem.Decode([]byte(certPEM))
	if bl == nil {
		return nil, ErrInvalidPEM
	}

	return x509.ParseCertificate(bl.Bytes)
}

// EncodePublicKey encodes an RSA public key into its PEM representation.
func EncodePublicKey(pubKey *rsa.PublicKey) (string, error) {
	pubKeyDER, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return "", err
	}

	pubKeyPEM := new(bytes.Buffer)

	if err := pem.Encode(pubKeyPEM, &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyDER,
	}); err != nil {
		return "", err
	}

	return pubKeyPEM.String(), nil
}

// Fingerprint returns the encoded fingerprint for the given certificate.
func Fingerprint(cert *x509.Certificate) string {
	var fingerprint bytes.Buffer

	/* #nosec. */
	for i, v := range md5.Sum(cert.Raw) {
		if i > 0 {
			_, _ = fmt.Fprintf(&fingerprint, ":")
		}

		_, _ = fmt.Fprintf(&fingerprint, "%02X", v)
	}

	return fingerprint.String()
}
