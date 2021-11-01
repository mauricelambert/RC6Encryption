![RC6Encryption logo](https://mauricelambert.github.io/info/python/security/rc6_background.png "RC6Encryption logo")

# RC6Encryption

## Description

This package implement the RC6 encryption.

## Requirements

This package require :
 - python3
 - python3 Standard Library

## Installation
```bash
pip install RC6Encryption
```

## Usages

### Command line

#### Module

```bash
python3 -m RC6Encryption rc6key -s secrets
```

#### Python executable

```bash
python3 RC6Encryption.pyz rc6key -s secrets
```

#### Command

##### Basic

```bash
rc6 rc6key -s secrets                               # encrypt "secrets" with rc6key sha256 as key
```

##### Advanced

```bash
rc6 rc6key -r 12 -l 5 -w 32 -s secrets              # encrypt "secrets" with rc6key sha256 as key (rounds=12, wbit=32, lgw=5)
echo secrets| rc6 rc6key --no-sha256 -i             # encrypt "secrets\n" with b'rc6key\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0' as key
rc6 rc6key -i secrets.txt                           # encrypt secrets.txt file with rc6key sha256 as key
rc6 rc6key -o encrypt.rc6 -s secrets                # encrypt "secrets" with rc6key sha256 as key and redirect the output to the encrypt.rc6 file
rc6 rc6key -i encrypt.rc6 -d                        # decrypt encrypt.rc6 with rc6key sha256 as key

# I do not recommend using encoding (input or output) with a large file size

## INPUT  ENCODING

rc6 rc6key -n base64 -s c2VjcmV0cw==                # encrypt "secrets" with rc6key sha256 as key ("c2VjcmV0cw==" = base64("secrets"))

## OUTPUT ENCODING

rc6 rc6key -s secrets -8                            # encrypt "secrets" with rc6key sha256 as key, base85-encoded output
rc6 rc6key -s secrets -6                            # encrypt "secrets" with rc6key sha256 as key, base64-encoded output
rc6 rc6key -s secrets -3                            # encrypt "secrets" with rc6key sha256 as key, base30-encoded output
rc6 rc6key -s secrets -1                            # encrypt "secrets" with rc6key sha256 as key, base16-encoded output
rc6 rc6key -s secrets -u                            # encrypt "secrets" with rc6key sha256 as key, uu-encoded output
```

### Python script

```python
from RC6Encryption import RC6Encryption
from hashlib import sha256

rc6 = RC6Encryption(sha256(b'abcdefghijklmnop').digest())
cipher = rc6.blocks_to_data(rc6.encrypt(b'abcdefghijklmnop'))
decipher = rc6.blocks_to_data(rc6.decrypt(cipher))
```

## Links

 - [Github Page](https://github.com/mauricelambert/RC6Encryption/)
 - [Documentation](https://mauricelambert.github.io/info/python/security/RC6Encryption.html)
 - [Pypi package](https://pypi.org/project/RC6Encryption/)
 - [Executable](https://mauricelambert.github.io/info/python/security/RC6Encryption.pyz)

## Help

```text
usage: RC6Encryption.py [-h] [--decryption] (--input-file [INPUT_FILE] | --input-string INPUT_STRING)
                        [--output-file OUTPUT_FILE]
                        [--base85 | --base64 | --base32 | --base16 | --uu | --output-encoding {base64,base16,uu,base85,base32}]
                        [--input-encoding {base64,base16,uu,base85,base32}] [--rounds ROUNDS] [--w-bit W_BIT]
                        [--lgw LGW] [--sha256 | --no-sha256]
                        key

This file performs RC6 encryption.

positional arguments:
  key                   Encryption key.

options:
  -h, --help            show this help message and exit
  --decryption, -d      Data decryption.
  --input-file [INPUT_FILE], --i-file [INPUT_FILE], -i [INPUT_FILE]
                        The file to be encrypted.
  --input-string INPUT_STRING, --string INPUT_STRING, -s INPUT_STRING
                        The string to be encrypted.
  --output-file OUTPUT_FILE, --o-file OUTPUT_FILE, -o OUTPUT_FILE
                        The output file.
  --base85, --85, -8    Base85 encoding as output format
  --base64, --64, -6    Base64 encoding as output format
  --base32, --32, -3    Base32 encoding as output format
  --base16, --16, -1    Base16 encoding as output format
  --uu, -u              UU encoding as output format
  --output-encoding {base64,base16,uu,base85,base32}, --o-encoding {base64,base16,uu,base85,base32}, -e {base64,base16,uu,base85,base32}
                        Output encoding.
  --input-encoding {base64,base16,uu,base85,base32}, --i-encoding {base64,base16,uu,base85,base32}, -n {base64,base16,uu,base85,base32}
                        Input encoding.
  --rounds ROUNDS, -r ROUNDS
                        RC6 rounds
  --w-bit W_BIT, -b W_BIT
                        RC6 w-bit
  --lgw LGW, -l LGW     RC6 lgw
  --sha256, --no-sha256
                        Use the sha256 of the key as the key. (default: True)
```

## Licence

Licensed under the [GPL, version 3](https://www.gnu.org/licenses/).
