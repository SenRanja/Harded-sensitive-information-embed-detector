package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

func main() {
	var pubKeyData = []byte(`
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArsyRh86Q2zUaR5U6Zzpu
X5YjrggSfB/4RoQrlwCAkgNalmd4VP4eP/qC8b/UH9hYzr57rL76O99t8drjWcA0
gkl0sMmsfO8jHt9XvYEM2AeRfwXTx8IKCw+wKnmf3ILqVTRz0i50St7VbXZjOx4M
06Ekb4hBjC4OBUdTT2fCqlzw0SxybCKO8HJ6guxDU6yn5d6y5U6jR0esEg0k+5a3
AaDhcSrKuMn08PTG7j3qy3nmywkVTRm1JjK7VfzZuj8RUDmKfQ2/2gDfrs/1H/7w
erjKzCrSCN9NvY8VKPZjKkn2fBtJHczGv8Ow7aOAdTJilVAGr9YvM8WzdeORFv7d
CwIDAQAB
-----END PUBLIC KEY-----`)
	pubKeyBlock, _ := pem.Decode(pubKeyData)
	if pubKeyBlock == nil {
		panic(errors.New("failed to parse public key"))
	}
	pubKey, err := x509.ParsePKIXPublicKey(pubKeyBlock.Bytes)
	if err != nil {
		panic(fmt.Sprintf("failed to parse public key: %v", err))
	}
	rsaPubKey, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		panic(errors.New("public key is not RSA"))
	}
	fmt.Printf("Parsed public key: %v\n", rsaPubKey)
}
