package protocol

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
	"github.com/teslamotors/vehicle-command/internal/authentication"
)

func SignMessageForFleet(privateKey ECDHPrivateKey, app string, message jwt.MapClaims) (string, error) {
	return authentication.SignMessageForFleet(privateKey, app, message)
}

func SignMessageForVehicle(privateKey ECDHPrivateKey, vin, app string, message jwt.MapClaims) (string, error) {
	return authentication.SignMessageForVehicle(privateKey, vin, app, message)
}

func LoadStringECDHKey(pemBlock string) (ECDHPrivateKey, error) {
	block, _ := pem.Decode([]byte(pemBlock))
	if block == nil {
		return nil, fmt.Errorf("%w: expected PEM encoding", authentication.ErrInvalidPrivateKey)
	}

	var ecdsaPrivateKey *ecdsa.PrivateKey
	var err error

	if block.Type == "EC PRIVATE KEY" {
		ecdsaPrivateKey, err = x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
	} else {
		privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		var ok bool
		if ecdsaPrivateKey, ok = privateKey.(*ecdsa.PrivateKey); !ok {
			return nil, fmt.Errorf("%w: only elliptic curve keys supported", authentication.ErrInvalidPrivateKey)
		}
	}

	if ecdsaPrivateKey.Curve != elliptic.P256() {
		return nil, fmt.Errorf("%w: only NIST-P256 keys supported", authentication.ErrInvalidPrivateKey)
	}
	return &authentication.NativeECDHKey{ecdsaPrivateKey}, nil
}
