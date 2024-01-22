package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"strings"
)

type PublicKey struct {
	N *big.Int
	E int
}

func extractPublicKey(dkimRecord string) ([]byte, error) {
	fields := strings.Fields(dkimRecord)
	for _, field := range fields {
		if strings.HasPrefix(field, "p=") {
			publicKeyBase64 := strings.TrimPrefix(field, "p=")
			publicKey, err := base64.StdEncoding.DecodeString(publicKeyBase64)
			if err != nil {
				return nil, err
			}
			return publicKey, nil
		}
	}
	return nil, fmt.Errorf("Public key not found in DKIM record")
}

func getDKIMPublicKey(domain, selector string) ([]byte, error) {
	query := fmt.Sprintf("%s._domainkey.%s", selector, domain)
	records, err := net.LookupTXT(query)
	if err != nil {
		return nil, err
	}
	for _, record := range records {
		// if strings.HasPrefix(record, fmt.Sprintf("%s=", selector)) {
		publicKey, err := extractPublicKey(record)
		if err != nil {
			return nil, err
		}
		return publicKey, nil
		// }
	}
	return nil, fmt.Errorf("DKIM public key not found")
}

func main() {
	domain := "gmail.com"
	selector := "20221208"
	publicKeyBytes, err := getDKIMPublicKey(domain, selector)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	// var pk PublicKey
	// _, err = asn1.Unmarshal(publicKeyBytes, &pk)
	// if err != nil {
	// 	log.Fatalf("Error unmarshaling ASN.1: %v", err)
	// }

	// // Print Modulus and Exponent
	// fmt.Printf("Modulus: %x\n", pk.N)
	// fmt.Printf("Exponent: %d\n", pk.E)

	block, _ := pem.Decode(publicKeyBytes)
	if block == nil {
		fmt.Println("Error: Failed to parse PEM block")
		return
	}

	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	rsaPublicKey, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		fmt.Println("Error: Public key is not an RSA key")
		return
	}

	fmt.Printf("Modulus: %x\n", rsaPublicKey.N)
	fmt.Printf("Exponent: %d\n", rsaPublicKey.E)
}
