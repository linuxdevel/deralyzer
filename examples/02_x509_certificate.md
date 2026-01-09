# X.509 Certificate Analysis Example

This example demonstrates how `deralyzer` parses and displays an X.509 certificate. Note how OIDs are resolved to human-readable names.

## Command

```bash
./deralyzer -in cert.pem --color
```

## Output

```text
SEQUENCE (3 elem)
  SEQUENCE (3 elem)
    [0] (1 elem)
      INTEGER 2
    INTEGER 15979854153328224520
    SEQUENCE (1 elem)
      OID 1.2.840.113549.1.1.11 (sha256WithRSAEncryption)
    SEQUENCE (3 elem)
      SET (1 elem)
        SEQUENCE (2 elem)
          OID 2.5.4.6 (countryName)
          PrintableString (2 byte) "US"
      SET (1 elem)
        SEQUENCE (2 elem)
          OID 2.5.4.10 (organizationName)
          PrintableString (10 byte) "Google Trust Services LLC"
      SET (1 elem)
        SEQUENCE (2 elem)
          OID 2.5.4.3 (commonName)
          PrintableString (23 byte) "GTS CA 1C3"
    SEQUENCE (2 elem)
      UTCTime (13 byte) "240129081829Z"
      UTCTime (13 byte) "240422081828Z"
    SEQUENCE (3 elem)
      SET (1 elem)
        SEQUENCE (2 elem)
          OID 2.5.4.3 (commonName)
          UTF8String (19 byte) "www.google.com"
    SEQUENCE (2 elem)
      SEQUENCE (2 elem)
        OID 1.2.840.113549.1.1.1 (rsaEncryption)
        NULL
      BIT STRING (270 byte) 00 ... (truncated)
    [3] (1 elem)
      SEQUENCE (9 elem)
        SEQUENCE (3 elem)
          OID 2.5.29.19 (basicConstraints)
          BOOLEAN TRUE
          OCTET STRING (2 byte)
            SEQUENCE (0 elem)
              <empty>
        SEQUENCE (2 elem)
          OID 2.5.29.15 (keyUsage)
          BOOLEAN TRUE
          OCTET STRING (3 byte)
            BIT STRING (7 bit) 1000011 (Digital Signature, Key Encipherment)
        ...
```

*Note: Nested structures inside OCTET STRINGs (like extensions) are automatically parsed and indented.*