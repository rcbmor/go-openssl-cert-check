package main

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

const (
	// possible values for pem.Block.Type.
	ECPrivateKeyBlockType = "EC PRIVATE KEY"
	RSAPrivateKeyBlockType = "RSA PRIVATE KEY"
	PrivateKeyBlockType = "PRIVATE KEY"
	PublicKeyBlockType = "PUBLIC KEY"
	CertificateBlockType = "CERTIFICATE"
	CertificateRequestBlockType = "CERTIFICATE REQUEST"
)

func decodePem(inpem string) *pem.Block {
	block, _ := pem.Decode([]byte(inpem))
	if block == nil {
		panic("failed to parse PEM")
	}
	return block
}

func parsePk(block *pem.Block) {

	// RSA or ECDSA Private Key in unencrypted PKCS#8 format
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		panic("failed to parse key: " + err.Error())
	}

	switch key.(type) {
	case *rsa.PrivateKey:
		fmt.Println("KEY RSA")
		key := key.(*rsa.PrivateKey)
		fmt.Printf("Key.PublicKey: %x\n", key.PublicKey)
	case *ecdsa.PrivateKey:
		fmt.Println("KEY ECDSA")
		key := key.(*ecdsa.PrivateKey)
		fmt.Printf("Key.PublicKey: %x\n", key.PublicKey)

	}
}

func checkCertKey(certKeyPEM string) {

	block := decodePem(certKeyPEM)
	fmt.Println("Block Type: ", block.Type)

	switch block.Type {
	case ECPrivateKeyBlockType:
		// ECDSA Private Key in ASN.1 format
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			panic("failed to parse key: " + err.Error())
		}
		fmt.Printf("Key.PublicKey: %x\n", key.PublicKey)
	case RSAPrivateKeyBlockType:
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			panic("failed to parse key: " + err.Error())
		}
		fmt.Printf("Key.PublicKey: %x\n", key.PublicKey)
	case PrivateKeyBlockType:
		parsePk(block)
	}
}

func checkCert(certPEM string) {

	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		panic("failed to parse certificate PEM")
	}
	fmt.Println("Block Type: ", block.Type)

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		panic("failed to parse certificate: " + err.Error())
	}

	fmt.Println("cert: ", cert.SignatureAlgorithm, cert.PublicKeyAlgorithm)
	fmt.Printf("cert.PublicKey: %x\n", cert.PublicKey)

}

func main() {

	const cert_PEM_ECDSA = `
-----BEGIN CERTIFICATE-----
MIICYjCCAggCCQCg9rw00d+BazAKBggqhkjOPQQDAjCBuDELMAkGA1UEBhMCQlIx
GjAYBgNVBAgMEVJpbyBHcmFuZGUgZG8gU3VsMRUwEwYDVQQHDAxQb3J0byBBbGVn
cmUxGDAWBgNVBAoMD1JpY2FyZG8gTW9yZWlyYTEYMBYGA1UECwwPUmljYXJkbyBN
b3JlaXJhMRgwFgYDVQQDDA9SaWNhcmRvIE1vcmVpcmExKDAmBgkqhkiG9w0BCQEW
GXJpY2FyZG8ubW9yZWlyYUBhemlvbi5jb20wHhcNMjAwMjI3MDQyOTMwWhcNMjEw
MjI2MDQyOTMwWjCBuDELMAkGA1UEBhMCQlIxGjAYBgNVBAgMEVJpbyBHcmFuZGUg
ZG8gU3VsMRUwEwYDVQQHDAxQb3J0byBBbGVncmUxGDAWBgNVBAoMD1JpY2FyZG8g
TW9yZWlyYTEYMBYGA1UECwwPUmljYXJkbyBNb3JlaXJhMRgwFgYDVQQDDA9SaWNh
cmRvIE1vcmVpcmExKDAmBgkqhkiG9w0BCQEWGXJpY2FyZG8ubW9yZWlyYUBhemlv
bi5jb20wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQgm9rsqilO3v/pFGtmKoFJ
piBA384V28nAwTE5/hTHmi6TUZqCIaQamIn7LRC8FllYXwp9xoLVamfnRP4G/1xt
MAoGCCqGSM49BAMCA0gAMEUCIQDlNNqsuM9ErcFojiO4ASMEjmruetP/ApACjExp
c4gCPwIgS4d+48cwyAbEr2yeEBXF18NhI0XDdJT69Mvqlo2UT/4=
-----END CERTIFICATE-----`
	const cert_key_PEM_ECDSA = `
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIOU5PHnFmkLkPWF1jHIEYtoVawMOAjozdqsaar4aYJFEoAoGCCqGSM49
AwEHoUQDQgAEIJva7KopTt7/6RRrZiqBSaYgQN/OFdvJwMExOf4Ux5ouk1GagiGk
GpiJ+y0QvBZZWF8KfcaC1Wpn50T+Bv9cbQ==
-----END EC PRIVATE KEY-----`

	const cert_PEM_RSA = `
-----BEGIN CERTIFICATE-----
MIIDgjCCAmoCCQCAF3e+S0XhVzANBgkqhkiG9w0BAQsFADCBgjELMAkGA1UEBhMC
QlIxGjAYBgNVBAgMEVJpbyBHcmFuZGUgZG8gU3VsMRUwEwYDVQQHDAxQb3J0byBB
bGVncmUxGDAWBgNVBAoMD1JpY2FyZG8gTW9yZWlyYTESMBAGA1UECwwJWW91ciBV
bml0MRIwEAYDVQQDDAlsb2NhbGhvc3QwHhcNMjAwMjI4MDEyNjMyWhcNMzAwMjI1
MDEyNjMyWjCBgjELMAkGA1UEBhMCQlIxGjAYBgNVBAgMEVJpbyBHcmFuZGUgZG8g
U3VsMRUwEwYDVQQHDAxQb3J0byBBbGVncmUxGDAWBgNVBAoMD1JpY2FyZG8gTW9y
ZWlyYTESMBAGA1UECwwJWW91ciBVbml0MRIwEAYDVQQDDAlsb2NhbGhvc3QwggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC3I/ise8c0Iz62ilupSQNANR9b
rvwvJFZRSiAckLgSfY/RBQsGdmkKh/aaNgwTGtEsKlVjAUDjLmzRigm2yXpiqnxf
aI88ViWzFHqSXmNYb6GlfKSCKfFXdnrCYrelfK/0jjdFtNrNFaaAfwlwipeuDOEt
F788ZHGEM2PbyaMNaGLHzruA4n3i3fr5La/vkZmpCxT5Gbpk7P9/A22ZNsVWawkg
iBL7o5SuODeh7em0Sck31ZYpV8e/eGJREIaHNAnxyMLoYWpU6cTu/P1CoWbe0QkG
RHadUZlw0Pu475C+qKmDlOuABtr/Z9Lf92wocBiONbF7ntWc0SiYBqSNtUgnAgMB
AAEwDQYJKoZIhvcNAQELBQADggEBAIB4d/hsa1CfrilpAHFL6xHwRrZsbzy4fvv6
auincj9zNNuvDBjiBq5oz+I6wDrmhGSV97ttETTJuV2rp8DFIFyDhTpivDoWbdHT
ZScL5NQTGCuGVaVE5uXcnKwbsiELfSC8zU02z4FWtPwWBUOjqEUUelKZgB0egh9a
W5eNmFW4HhpnXs1DBqURFl4J82UsCxQAlKAun6XtPnTvkBd830yRuK+PUeHDv566
TEC/K3zTAEqG8xU1EFejMXip4xt8B/Las0WGmXcG3pir8G42+VAN8DmzXf6GoXV3
MHVGQN/r2pwtn9h9yhqcGwE0MqiiPAMcUxChWRzOi6E9MG9jKL8=
-----END CERTIFICATE-----`
	const cert_key_PEM_RSA = `
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC3I/ise8c0Iz62
ilupSQNANR9brvwvJFZRSiAckLgSfY/RBQsGdmkKh/aaNgwTGtEsKlVjAUDjLmzR
igm2yXpiqnxfaI88ViWzFHqSXmNYb6GlfKSCKfFXdnrCYrelfK/0jjdFtNrNFaaA
fwlwipeuDOEtF788ZHGEM2PbyaMNaGLHzruA4n3i3fr5La/vkZmpCxT5Gbpk7P9/
A22ZNsVWawkgiBL7o5SuODeh7em0Sck31ZYpV8e/eGJREIaHNAnxyMLoYWpU6cTu
/P1CoWbe0QkGRHadUZlw0Pu475C+qKmDlOuABtr/Z9Lf92wocBiONbF7ntWc0SiY
BqSNtUgnAgMBAAECggEBAJaILqI3q2kjfyyzVNw0c0OXZosJradiCsEOWI6iNWqd
YlS//Gv3cCeD0iK3Qf2CEWRn939FTHxvcGpbN9jSipIG5+vUGcfSV3J25rjgdHAA
cbGAXgfPSdxGOmkEk0am0koFi1D0ctQXc6AyyyOCB2K8m2lhF4MgXF35j57cgfVF
7t9droes/ms3mBP8i5HHwPnsGhSeASqLUNDu9Kln0TcSjZggqZR87VDSHW3wlRom
UDKoce7QnfCOacyItbGx3/z9TFNRD/s8qMBPT0QYxc1LtzP17EmLzdEraX2mx4g0
Kve2TgXE5bgSIzwLW+IPA4zfXB6mLGS4IpOuC7Y8wEECgYEA6RwJZVWIy9zsLFxj
K+Cwpj8HGaJzFOPn1BTRC4uu682nrPDYC5g9YJZVOiIHRvR81u/QKbvEP3CmDJ1S
ubRUwLP3u85Mj41ocliRUAUXN7dcxcePrrsWwBj3piDmTLKm+Dnt200sEWEweFIQ
OMa96oFD3+OwwO3GDOxojs+GUakCgYEAyR/NQShPpgIdNX5VwxUUOaVge055/CCa
IWoo7YEbELlQdsSKLEe1p4KgmT5dqIi7p9rT9UyoqterOJ9ojRyXw75fBZ3A0TdV
qHLVrOHM0n4I7t0WX8Copoa9SGVzaKn1F9z4Oa1HzyBMZoUW5U2buNujqo680Bpe
PVsg7gMIjU8CgYBGkM0rVtQ9WlhIKYN/4dm3ybadhPavaTphkheiFhvSmAPdL19H
S0OxPHD6Uxi+2v37lsb+CzAiQDiT8v/65WMOnqwstwuoHRd0HemHPrNDk4dK+9k7
/LirWCOHr8fnieFPnUGqtFbVwAULN1Rfy5HsLktcuDFmhdQBT4NrT9kKWQKBgQCB
T0kQU3KiMUnGUuug+bR/O6zEmrgjOnLeePrHePKF1h+9vK95uME6aeoHnOlqqj68
tR0B4b+v1+nmBdeaon+RApzlZ3/JA+K24t4uwR6HVzE3Ij54Yc4NAyQ/n7qL2HoU
VaXir14z9Xgpkfgehb9RIyYfSpZq1gkxOZ36aUjeUQKBgFOlW3QS5bHVNUKDf2ZD
MIVq+KwRYIW/8bmf18xvWZjv4K67j6LXdCEdt8MnHxRxZpYRBXHQ/vC/frGqFh6D
oDi848wtsF9KqGD8Vj4j1cbxwVK/zUYikTojcr5fDwKpZPDepwgipwtk4aGllbSK
kFX3q5W5pCtcdtBd1B+1iXPr
-----END PRIVATE KEY-----`

	checkCert(cert_PEM_RSA)
	fmt.Println("--------");
	checkCertKey(cert_key_PEM_RSA)
	fmt.Println("--------");
	checkCert(cert_PEM_ECDSA)
	fmt.Println("--------");
	checkCertKey(cert_key_PEM_ECDSA)
	fmt.Println("--------");

}
