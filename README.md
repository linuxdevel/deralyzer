# deralyzer

**deralyzer** is a lightweight, robust C++ command-line tool for analyzing, visualizing, and debugging ASN.1 structures in DER or PEM format. It leverages OpenSSL to parse generic ASN.1 objects while providing specialized insights for X.509 certificates, PKCS#7/CMS containers, and other common cryptographic artifacts.

## Features

- **ASN.1 Visualization**: displays the tree structure of any ASN.1 file (Sequence, Set, Integer, OID, etc.).
- **Format Auto-detection**: Automatically detects PEM or DER input formats.
- **Deep Inspection**: Recursively "tunnels" into `OCTET STRING` and `BIT STRING` encapsulations to reveal hidden nested structures (e.g., X.509 Extensions, PKCS#7 content).
- **OID Resolution**: Translates numeric Object Identifiers (OIDs) into human-readable names using an internal database and a configurable `deralyzer.cfg` file.
- **DER Compliance Checks**: Validates encoding rules (e.g., proper boolean values, minimal integer encoding, correct bit string padding).
- **Hex Dumps**: Provides clear hex/ASCII dumps for binary blobs.
- **Color Output**: Syntax highlighting for better readability in the terminal.

## Dependencies

- **C++17** compiler (GCC, Clang)
- **OpenSSL** development libraries (`libssl-dev` or `openssl-devel`)

## Build

You can compile `deralyzer` using the provided Makefile:

```bash
make
```

Or compile directly with `g++`:

```bash
g++ -o deralyzer src/main.cpp -lssl -lcrypto
```

### Additional Makefile Targets

- `make test`  - Build and run basic tests with generated RSA keys
- `make install`  - Install the binary and config file (prompts for installation prefix, default: `/usr/local`)
- `make clean` - Remove build artifacts and the compiled binary

## Usage

```bash
./deralyzer -in <filename> [options]
```

### Options

| Option | Description |
|--------|-------------|
| `-in <file>` | Path to the input file (required). |
| `-inform <der\|pem>` | Force input format (default: auto-detect). |
| `-outform <text\|hex\|tree>` | Output format. `tree` is the default structural view. `hex` outputs a raw hex dump. |
| `-v` | Verbose mode (currently reserved for future use). |
| `--color` | Enable colored terminal output. |
| `--full-output` | Disable truncation of long hex dumps (default truncates after 32 bytes). |

### Configuration

The tool looks for a `deralyzer.cfg` file in the same directory as the executable. You can use this file to define custom OID descriptions or add warnings for specific OIDs (e.g., deprecated algorithms).

**Format:**
```json
{
  "1.2.840.113549.1.1.1": {
    "description": "RSA Encryption"
  },
  "1.2.840.113549.1.1.4": {
    "description": "MD5 with RSA Encryption",
    "warning": true
  }
}
```

The config file is in JSON format. Each OID is a key with an object containing:
- `description` - Human-readable name for the OID
- `warning` (optional) - Set to `true` to flag this OID in red (useful for deprecated algorithms)

## Examples

**Analyze a PEM certificate with color:**
```bash
./deralyzer -in cert.pem --color
```

**Analyze a binary DER file (e.g., PKCS#7):**
```bash
./deralyzer -in signed_data.p7b --color --full-output
```

**View raw hex dump of a file:**
```bash
./deralyzer -in data.bin -outform hex
```


## Author

**Arne Brune Olsen**

## Contributions

Contributions are welcome! Please make a pull request or open an issue if you have ideas for improvements. Your help in making this project better is greatly appreciated.