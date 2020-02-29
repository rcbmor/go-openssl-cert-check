# go-openssl-cert-check
Example code to check certificate and key pair.

## Issue with EC parameters section
When we create a ECDSA key, the initial section is not the key but the *EC parameters*:

```
-----BEGIN EC PARAMETERS-----
BggqhkjOPQMBBw==
-----END EC PARAMETERS-----
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIPCNIWnw5gSBhugq3IG3n3iOfsywyqQcsmU+8vhlrv6koAoGCCqGSM49
AwEHoUQDQgAE0DjZbPGaH8asOkgNswIFDX3jdDimAl5tziyom5InUOLF21RtHnUc
GuIhq9f/v8xC48ZSU3PvknKOXTyOcCMu/Q==
-----END EC PRIVATE KEY-----
```

The API for x509 Parse Key expects a *begin private key* and raises an error!
In order to make the code work, I had to remove the *EC parameters* section leaving only the private key:
```
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIPCNIWnw5gSBhugq3IG3n3iOfsywyqQcsmU+8vhlrv6koAoGCCqGSM49
AwEHoUQDQgAE0DjZbPGaH8asOkgNswIFDX3jdDimAl5tziyom5InUOLF21RtHnUc
GuIhq9f/v8xC48ZSU3PvknKOXTyOcCMu/Q==
-----END EC PRIVATE KEY-----
```

