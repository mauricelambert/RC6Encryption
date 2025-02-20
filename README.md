![RC6Encryption logo](https://mauricelambert.github.io/info/python/security/rc6_small_background.png "RC6Encryption logo")

# RC6Encryption

## Description

This pure python package implements the RC6 encryption (ECB and CBC encryption mode).

> All encryption and decryption mode are tested, i compare the result with https://www.lddgo.net/en/encrypt/rc6 API.
>> The ECB mode is not recommended, it's the basic encryption for block cipher, you should always use CBC encryption for data greater than 16 bytes.

## Requirements

This package require:

 - python3
 - python3 Standard Library

## Installation

### Pip

```bash
python3 -m pip install RC6Encryption
```

### Git

```bash
git clone "https://github.com/mauricelambert/RC6Encryption.git"
cd "RC6Encryption"
python3 -m pip install .
```

### Wget

```bash
wget https://github.com/mauricelambert/RC6Encryption/archive/refs/heads/main.zip
unzip main.zip
cd RC6Encryption-main
python3 -m pip install .
```

### cURL

```bash
curl -O https://github.com/mauricelambert/RC6Encryption/archive/refs/heads/main.zip
unzip main.zip
cd RC6Encryption-main
python3 -m pip install .
```

## Usages

### Recommended options

```bash
rc6 [key] -m CBC -6 -o [secrets.cipher] -i [secrets.file]            # encryption
rc6 [key] -m CBC -n base64 -i [secrets.cipher] -o [decipher.file] -d # decryption
```

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
rc6 rc6key -r 12 -l 5 -w 32 -s secrets              # encrypt "secrets" with rc6key sha256 as key (rounds=12, wbit=32, lgw=5) in ECB mode
echo secrets| rc6 rc6key --no-sha256 -i             # encrypt "secrets\n" with key and PKCS 5/7 padding in ECB mode
rc6 rc6key -m CBC -I IVTEST -i secrets.txt          # encrypt secrets.txt file content with rc6key sha256 as key and CBC mode and IVTEST as IV
rc6 rc6key -o encrypt.rc6 -s secrets -m CBC         # encrypt "secrets" with rc6key sha256 as key, IVTEST as IV and redirect the output to the encrypt.rc6 file using CBC encryption mode and random IV
rc6 rc6key -i encrypt.rc6 -d -m CBC                 # decrypt encrypt.rc6 with rc6key sha256 as key using CBC encryption mode

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

#### RC6 encryption using CBC (recommended)

```python
from RC6Encryption import RC6Encryption

rc6 = RC6Encryption(b'abcdefghijklm')
iv, encrypt = rc6.data_encryption_CBC(b'abcdefghijklmnopabcdefghijklmnopabcdefghijklm')             # Random IV
plaintext = rc6.data_decryption_CBC(encrypt, iv)

iv, encrypt = rc6.data_encryption_CBC(b'abcdefghijklmnopabcdefghijklmnopabcdefghijklm', b'IVTEST')  # Generate your IV, be careful, an IV with size less than 16 bytes is not recommended
plaintext = rc6.data_decryption_CBC(encrypt, iv)
```

#### RC6 encryption using ECB (not recommended)

```python
from RC6Encryption import RC6Encryption

rc6 = RC6Encryption(b'abcdefghijklm')
encrypt = rc6.data_encryption_ECB(b'abcdefghijklmnopabcdefghijklmnopabcdefghijklm')
plaintext = rc6.data_decryption_ECB(encrypt)
```

#### Low level API

```python
from RC6Encryption import RC6Encryption
from hashlib import sha256

rc6 = RC6Encryption(sha256(b'abcdefghijklmnop').digest())
cipher = rc6.blocks_to_data(rc6.encrypt(b'abcdefghijklmnop'))
decipher = rc6.blocks_to_data(rc6.decrypt(cipher))
```

## Links

 - [Pypi](https://pypi.org/project/RC6Encryption/)
 - [Github](https://github.com/mauricelambert/RC6Encryption/)
 - [Documentation](https://mauricelambert.github.io/info/python/security/RC6Encryption.html)
 - [Executable](https://mauricelambert.github.io/info/python/security/RC6Encryption.pyz)
 - [Python Windows executable](https://mauricelambert.github.io/info/python/security/RC6Encryption.exe)

## Help

```text
usage: RC6Encryption.py [-h] [--mode {CBC,ECB}] [--decryption] (--input-file [INPUT_FILE] | --input-string INPUT_STRING) [--output-file OUTPUT_FILE]
                        [--base85 | --base64 | --base32 | --base16 | --output-encoding {base32,base16,base64,base85}]
                        [--input-encoding {base32,base16,base64,base85}] [--rounds ROUNDS] [--w-bit W_BIT] [--iv IV] [--lgw LGW] [--sha256 | --no-sha256]
                        key

This script performs RC6 encryption.

positional arguments:
  key                   Encryption key.

options:
  -h, --help            show this help message and exit
  --mode {CBC,ECB}, -m {CBC,ECB}
                        Ecryption mode, for CBC encryption IV is write on the first 16 bytes of the encrypted data.
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
  --output-encoding {base32,base16,base64,base85}, --o-encoding {base32,base16,base64,base85}, -e {base32,base16,base64,base85}
                        Output encoding.
  --input-encoding {base32,base16,base64,base85}, --i-encoding {base32,base16,base64,base85}, -n {base32,base16,base64,base85}
                        Input encoding.
  --rounds ROUNDS, -r ROUNDS
                        RC6 rounds
  --w-bit W_BIT, -b W_BIT
                        RC6 w-bit
  --iv IV, -I IV        IV for CBC mode only, for decryption if IV is not set the 16 first bytes are used instead.
  --lgw LGW, -l LGW     RC6 lgw
  --sha256, --no-sha256
                        Use the sha256 hash of the key as the key.
```

## Licence

Licensed under the [GPL, version 3](https://www.gnu.org/licenses/).
