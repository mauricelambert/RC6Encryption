#!/usr/bin/env python3
# -*- coding: utf-8 -*-

###################
#    This package implements RC6 encryption.
#    Copyright (C) 2021, 2023, 2024  Maurice Lambert

#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.

#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.

#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <https://www.gnu.org/licenses/>.
###################

"""
This package implements RC6 encryption.

>>> rc6 = RC6Encryption(b'abcdefghijklmnop', 12, 32, 5)
>>> c = rc6.blocks_to_data(rc6.encrypt(b'abcdefghijklmnop'))
>>> rc6.blocks_to_data(rc6.decrypt(c))
b'abcdefghijklmnop'
>>>

>>> from urllib.request import urlopen, Request
>>> from json import dumps, load
>>> rc6 = RC6Encryption(b'abcdefghijklmnop')
>>> encrypt = rc6.blocks_to_data(rc6.encrypt(b'abcdefghijklmnop')).hex()
>>> encrypt
'bb05a4b6c46a24a8bf70e1e2c0a33e51'
>>> encrypt == load(urlopen(Request("https://www.lddgo.net/api/RC6?lang=en", headers={"Content-Type": "application/json;charset=UTF-8"}, data=dumps({"inputContent":"abcdefghijklmnop","model":"ECB","padding":"nopadding","inputPassword":"abcdefghijklmnop","inputIv":"","inputFormat":"string","outputFormat":"hex","charset":"UTF-8","encrypt":True}).encode())))["data"]
True
>>> encrypt = rc6.blocks_to_data(rc6.encrypt(b'abcdefghijklmnop') + rc6.encrypt(b'abcdefghijklmnop')).hex()
>>> encrypt
'bb05a4b6c46a24a8bf70e1e2c0a33e51bb05a4b6c46a24a8bf70e1e2c0a33e51'
>>> encrypt == load(urlopen(Request("https://www.lddgo.net/api/RC6?lang=en", headers={"Content-Type": "application/json;charset=UTF-8"}, data=dumps({"inputContent":"abcdefghijklmnopabcdefghijklmnop","model":"ECB","padding":"nopadding","inputPassword":"abcdefghijklmnop","inputIv":"","inputFormat":"string","outputFormat":"hex","charset":"UTF-8","encrypt":True}).encode())))["data"]
True
>>> pkcs5_7padding(b'abcdefghijklmno')
b'abcdefghijklmno\\x01'
>>> remove_pkcs_padding(pkcs5_7padding(b'abcdefghijklmno')) == b'abcdefghijklmno'
True
>>> pkcs5_7padding(b'abcdefghijklm')
b'abcdefghijklm\\x03\\x03\\x03'
>>> remove_pkcs_padding(pkcs5_7padding(b'abcdefghijklm')) == b'abcdefghijklm'
True
>>> rc6 = RC6Encryption(b'abcdefghijklm')
>>> encrypt = rc6.blocks_to_data(rc6.encrypt(pkcs5_7padding(b'abcdefghijklm'))).hex()
>>> encrypt
'c5ee3509788662a5711822d5e01eb4c0'
>>> encrypt == load(urlopen(Request("https://www.lddgo.net/api/RC6?lang=en", headers={"Content-Type": "application/json;charset=UTF-8"}, data=dumps({"inputContent":"abcdefghijklm","model":"ECB","padding":"pkcs5padding","inputPassword":"abcdefghijklm","inputIv":"","inputFormat":"string","outputFormat":"hex","charset":"UTF-8","encrypt":True}).encode())))["data"]
True
>>> rc6 = RC6Encryption(b'abcd')
>>> encrypt = rc6.data_encryption_ECB(b'abcdefghijklmnop').hex()
>>> encrypt
'78a64e37f7455f30aaf40750be1a065701bf2f308216c43c42c794285ffbf99e'
>>> encrypt == load(urlopen(Request("https://www.lddgo.net/api/RC6?lang=en", headers={"Content-Type": "application/json;charset=UTF-8"}, data=dumps({"inputContent":"abcdefghijklmnop","model":"ECB","padding":"pkcs5padding","inputPassword":"abcd","inputIv":"","inputFormat":"string","outputFormat":"hex","charset":"UTF-8","encrypt":True}).encode())))["data"]
True
>>> rc6.data_decryption_ECB(bytes.fromhex('78a64e37f7455f30aaf40750be1a065701bf2f308216c43c42c794285ffbf99e'))
b'abcdefghijklmnop'
>>> rc6 = RC6Encryption(b'abcd')
>>> iv, encrypt = rc6.data_encryption_CBC(b'abcdefghijklmnopabcdefghijklmnopabcdefghijklm', b'IVTEST')
>>> encrypt = encrypt.hex()
>>> iv
b'IVTESTIVTESTIVTE'
>>> encrypt
'8de91e69865825bbb6e1785e3b498f3a89708aaa2aff01a688cf9836bd7eea56c04fa0a14706d79bd94846e905bf070b'
>>> encrypt == load(urlopen(Request("https://www.lddgo.net/api/RC6?lang=en", headers={"Content-Type": "application/json;charset=UTF-8"}, data=dumps({"inputContent":"abcdefghijklmnopabcdefghijklmnopabcdefghijklm","model":"CBC","padding":"pkcs5padding","inputPassword":"abcd","inputIv":iv.decode('latin-1'),"inputFormat":"string","outputFormat":"hex","charset":"UTF-8","encrypt":True}).encode())))["data"]
True
>>> rc6.data_decryption_CBC(bytes.fromhex('8de91e69865825bbb6e1785e3b498f3a89708aaa2aff01a688cf9836bd7eea56c04fa0a14706d79bd94846e905bf070b'), iv)
b'abcdefghijklmnopabcdefghijklmnopabcdefghijklm'
>>> 

~# rc6 mykey -s mydata -6
0wS4TwM292nGa378oBuz/w==
~# rc6 mykey -s 0wS4TwM292nGa378oBuz/w== -n base64 -d
mydata
~# rc6 mykey --no-sha256 -r 12 -s mydata -6
vzliI0irqi3tZ8fULxJ14g==
~# rc6 mykey --no-sha256 -r 12 -s vzliI0irqi3tZ8fULxJ14g== -n base64 -d
mydata
~# rc6 mykey -m CBC -I myiv -s mydata -1
6D7969766D7969766D7969766D796976BF2F024053F74FE27920DE5C274935A6
~# rc6 mykey -m CBC -d -s 6D7969766D7969766D7969766D796976BF2F024053F74FE27920DE5C274935A6 -n base16
mydata
~# 

1 items passed all tests:
  32 tests in RC6Encryption
32 tests in 25 items.
32 passed and 0 failed.
Test passed.
"""

"""
Algorithm:

 - Key generation:
    S [0] = P32
    for i = 1 to 2r + 3 do
    {
        S [i] = S [i - 1] + Q32
    }
    A = B = i = j = 0
    v = 3 X max{c, 2r + 4}
    for s = 1 to v do
    {
        A = S [i] = (S [i] + A + B) <<< 3
        B = L [j] = (L [j] + A + B) <<< (A + B)
        i = (i + 1) mod (2r + 4)
        j = (j + 1) mod c
    }

 - Encryption:
    B = B + S[0]
    D = D + S[1]
    for i = 1 to r do
    {
        t = (B * (2B + 1)) <<< lg w
        u = (D * (2D + 1)) <<< lg w
        A = ((A ^ t) <<< u) + S[2i]
        C = ((C ^ u) <<< t) + S[2i + 1] 
        (A, B, C, D)  =  (B, C, D, A)
    }
    A = A + S[2r + 2]
    C = C + S[2r + 3]

 - Decryption:
    C = C - S[2r + 3]
    A = A - S[2r + 2]

    for i = r downto 1 do
    {
        (A, B, C, D) = (D, A, B, C)
        u = (D * (2D + 1)) <<< lg w
        t = (B * (2B + 1)) <<< lg w
        C = ((C - S[2i + 1]) >>> t) ^ u
        A = ((A - S[2i]) >>> u) ^ t
    }
    D = D - S[1]
    B = B - S[0]
"""

__version__ = "1.0.0"
__author__ = "Maurice Lambert"
__author_email__ = "mauricelambert434@gmail.com"
__maintainer__ = "Maurice Lambert"
__maintainer_email__ = "mauricelambert434@gmail.com"
__description__ = "This package implements RC6 encryption."
license = "GPL-3.0 License"
__url__ = "https://github.com/mauricelambert/RC6Encryption"

copyright = """
RC6Encryption  Copyright (C) 2021, 2023, 2024  Maurice Lambert
This program comes with ABSOLUTELY NO WARRANTY.
This is free software, and you are welcome to redistribute it
under certain conditions.
"""
__license__ = license
__copyright__ = copyright

print(copyright)

__all__ = ["RC6Encryption", "pkcs5_7padding"]

from base64 import (
    b85encode,
    b64encode,
    b32encode,
    b16encode,
    b85decode,
    b64decode,
    b32decode,
    b16decode,
)
from argparse import Namespace, ArgumentParser, FileType, BooleanOptionalAction
from locale import getpreferredencoding
from typing import Tuple, List, Union
from collections.abc import Iterator
from sys import exit, stdin, stdout
from warnings import simplefilter
from contextlib import suppress
from os import device_encoding
from functools import partial
from hashlib import sha256
from os import urandom

try:
    from binascii import a2b_hqx, b2a_hqx
except ImportError:
    uu_encoding = False
else:
    uu_encoding = True

basetwo = partial(int, base=2)
unblock = partial(int.to_bytes, length=4, byteorder="little")


class RC6Encryption:

    """
    This class implements the RC6 encryption.

    Rounds possible values: {12, 16, 20}
    """

    P32 = 0xB7E15163
    Q32 = 0x9E3779B9

    def __init__(
        self, key: bytes, rounds: int = 20, w_bit: int = 32, lgw: int = 5
    ):
        self.key_bytes = key
        self.rounds = rounds
        self.w_bit = w_bit
        self.lgw = lgw

        self.round2_2 = rounds * 2 + 2
        self.round2_3 = self.round2_2 + 1
        self.round2_4 = self.round2_3 + 1

        self.modulo = 2**w_bit

        (
            self.key_binary_blocks,
            self.key_integer_reverse_blocks,
        ) = self.get_blocks(key)
        self.key_blocks_number = len(self.key_binary_blocks)

        self.rc6_key = [self.P32]

        self.key_generation()

    @staticmethod
    def enumerate_blocks(data: bytes) -> Iterator[Tuple[int, int, int, int]]:
        """
        This function returns a tuple of 4 integers for each blocks.
        """

        _, blocks = RC6Encryption.get_blocks(data)

        while blocks:
            a, b, c, d, *blocks = blocks
            yield a, b, c, d

    @staticmethod
    def get_blocks(data: bytes) -> Tuple[List[str], List[int]]:
        """
        This function returns blocks (binary strings and integers) from data.
        """

        binary_blocks = []
        integer_blocks = []
        block = ""

        for i, char in enumerate(data):
            if i and not i % 4:
                binary_blocks.append(block)
                integer_blocks.append(basetwo(block))
                block = ""
            block = f"{char:0>8b}{block}"

        binary_blocks.append(block)
        integer_blocks.append(basetwo(block))

        return binary_blocks, integer_blocks

    @staticmethod
    def blocks_to_data(blocks: List[int]) -> bytes:
        """
        This function returns data from blocks (binary strings).
        """

        data = b""

        for block in blocks:
            data += unblock(block)

        return data

    def right_rotation(self, x: int, n: int) -> int:
        """
        This function perform a right rotation.
        """

        mask = (2**n) - 1
        mask_bits = x & mask
        return (x >> n) | (mask_bits << (self.w_bit - n))

    def left_rotation(self, x: int, n: int) -> int:
        """
        This function perform a left rotation (based on right rotation).
        """

        return self.right_rotation(x, self.w_bit - n)

    def key_generation(self) -> List[int]:
        """
        This function generate the key.
        """

        for i in range(0, self.round2_3):
            self.rc6_key.append((self.rc6_key[i] + self.Q32) % self.modulo)

        a = b = i = j = 0
        v = 3 * (
            self.key_blocks_number
            if self.key_blocks_number > self.round2_4
            else self.round2_4
        )

        for i_ in range(v):
            a = self.rc6_key[i] = self.left_rotation(
                (self.rc6_key[i] + a + b) % self.modulo, 3
            )
            b = self.key_integer_reverse_blocks[j] = self.left_rotation(
                (self.key_integer_reverse_blocks[j] + a + b) % self.modulo,
                (a + b) % 32,
            )
            i = (i + 1) % (self.round2_4)
            j = (j + 1) % self.key_blocks_number

        return self.rc6_key

    def data_encryption_ECB(self, data: bytes) -> bytes:
        """
        This function performs full encryption using ECB mode:
            - add PKCS (5/7) padding
            - get blocks
            - encrypt all blocks using ECB mode
            - convert blocks in bytes
            - returns bytes
        """

        data = pkcs5_7padding(data)
        encrypted = []

        for block in self.enumerate_blocks(data):
            encrypted.extend(self.encrypt(block))

        return self.blocks_to_data(encrypted)

    def data_decryption_ECB(self, data: bytes) -> bytes:
        """
        This function performs full decryption using ECB mode:
            - get blocks
            - decrypt all blocks using ECB mode
            - convert blocks in bytes
            - remove PKCS (5/7) padding
            - returns bytes
        """

        decrypted = []

        for block in self.enumerate_blocks(data):
            decrypted.extend(self.decrypt(block))

        return remove_pkcs_padding(self.blocks_to_data(decrypted))

    def data_encryption_CBC(
        self, data: bytes, iv: bytes = None
    ) -> Tuple[bytes, bytes]:
        """
        This function performs full encryption using CBC mode:
            - get/generate the IV
            - add PKCS (5/7) padding
            - get blocks
            - encrypt all blocks using CBC mode
            - convert blocks in bytes
            - returns bytes
        """

        if iv is None:
            _iv = urandom(16)
        else:
            iv_length = len(iv)
            _iv = bytes(iv[i % iv_length] for i in range(16))

        _, iv = self.get_blocks(_iv)

        data = pkcs5_7padding(data)
        encrypted = []

        for block in self.enumerate_blocks(data):
            block = (
                block[0] ^ iv[0],
                block[1] ^ iv[1],
                block[2] ^ iv[2],
                block[3] ^ iv[3],
            )
            iv = self.encrypt(block)
            encrypted.extend(iv)

        return _iv, self.blocks_to_data(encrypted)

    def data_decryption_CBC(self, data: bytes, iv: bytes) -> bytes:
        """
        This function performs full decryption using CBC mode:
            - get blocks
            - decrypt all blocks using CBC mode
            - convert blocks in bytes
            - remove PKCS (5/7) padding
            - returns bytes
        """

        _, iv = self.get_blocks(iv)
        decrypted = []

        for block in self.enumerate_blocks(data):
            decrypted_block = self.decrypt(block)
            decrypted.extend(
                (
                    decrypted_block[0] ^ iv[0],
                    decrypted_block[1] ^ iv[1],
                    decrypted_block[2] ^ iv[2],
                    decrypted_block[3] ^ iv[3],
                )
            )
            iv = block

        return remove_pkcs_padding(self.blocks_to_data(decrypted))

    def encrypt(
        self, data: Union[bytes, Tuple[int, int, int, int]]
    ) -> List[int]:
        """
        This functions performs RC6 encryption on only one block.

        This function returns a list of 4 integers.
        """

        if isinstance(data, bytes):
            _, data = self.get_blocks(data)
        a, b, c, d = data

        b = (b + self.rc6_key[0]) % self.modulo
        d = (d + self.rc6_key[1]) % self.modulo

        for i in range(1, self.rounds + 1):
            t = self.left_rotation(b * (2 * b + 1) % self.modulo, self.lgw)
            u = self.left_rotation(d * (2 * d + 1) % self.modulo, self.lgw)
            tmod = t % self.w_bit
            umod = u % self.w_bit
            a = (
                self.left_rotation(a ^ t, umod) + self.rc6_key[2 * i]
            ) % self.modulo
            c = (
                self.left_rotation(c ^ u, tmod) + self.rc6_key[2 * i + 1]
            ) % self.modulo
            a, b, c, d = b, c, d, a

        a = (a + self.rc6_key[self.round2_2]) % self.modulo
        c = (c + self.rc6_key[self.round2_3]) % self.modulo

        return [a, b, c, d]

    def decrypt(self, data: bytes) -> List[int]:
        """
        This function performs a RC6 decryption.
        """

        if isinstance(data, bytes):
            _, data = self.get_blocks(data)
        a, b, c, d = data

        c = (c - self.rc6_key[self.round2_3]) % self.modulo
        a = (a - self.rc6_key[self.round2_2]) % self.modulo

        for i in range(self.rounds, 0, -1):
            (a, b, c, d) = (d, a, b, c)
            u = self.left_rotation(d * (2 * d + 1) % self.modulo, self.lgw)
            t = self.left_rotation(b * (2 * b + 1) % self.modulo, self.lgw)
            tmod = t % self.w_bit
            umod = u % self.w_bit
            c = (
                self.right_rotation(
                    (c - self.rc6_key[2 * i + 1]) % self.modulo, tmod
                )
                ^ u
            )
            a = (
                self.right_rotation(
                    (a - self.rc6_key[2 * i]) % self.modulo, umod
                )
                ^ t
            )

        d = (d - self.rc6_key[1]) % self.modulo
        b = (b - self.rc6_key[0]) % self.modulo

        return [a, b, c, d]


def remove_pkcs_padding(data: bytes) -> bytes:
    """
    This function implements PKCS 5/7 padding.
    """

    return data[: data[-1] * -1]


def pkcs5_7padding(data: bytes, size: int = 16) -> bytes:
    """
    This function implements PKCS 5/7 padding.
    """

    mod = len(data) % size
    padding = size - mod
    data = data + padding.to_bytes() * padding
    return data


def parse_args() -> Namespace:
    """
    This function parse command line arguments.
    """

    parser = ArgumentParser(description="This script performs RC6 encryption.")

    parser.add_argument(
        "--mode",
        "-m",
        help=(
            "Ecryption mode, for CBC encryption IV"
            " is write on the first 16 bytes of the encrypted data."
        ),
        default="ECB",
        choices={"ECB", "CBC"},
    )

    parser.add_argument(
        "--decryption", "-d", help="Data decryption.", action="store_true"
    )

    input_ = parser.add_mutually_exclusive_group(required=True)
    input_.add_argument(
        "--input-file",
        "--i-file",
        "-i",
        type=FileType("rb"),
        default=stdin.buffer,
        help="The file to be encrypted.",
        nargs="?",
    )
    input_.add_argument(
        "--input-string", "--string", "-s", help="The string to be encrypted."
    )

    parser.add_argument(
        "--output-file",
        "--o-file",
        "-o",
        type=FileType("wb"),
        default=stdout.buffer,
        help="The output file.",
    )

    output_encoding = parser.add_mutually_exclusive_group()
    output_encoding.add_argument(
        "--base85",
        "--85",
        "-8",
        help="Base85 encoding as output format",
        action="store_true",
    )
    output_encoding.add_argument(
        "--base64",
        "--64",
        "-6",
        help="Base64 encoding as output format",
        action="store_true",
    )
    output_encoding.add_argument(
        "--base32",
        "--32",
        "-3",
        help="Base32 encoding as output format",
        action="store_true",
    )
    output_encoding.add_argument(
        "--base16",
        "--16",
        "-1",
        help="Base16 encoding as output format",
        action="store_true",
    )
    if uu_encoding:
        output_encoding.add_argument(
            "--uu",
            "-u",
            help="UU encoding as output format",
            action="store_true",
        )
    output_encoding.add_argument(
        "--output-encoding",
        "--o-encoding",
        "-e",
        help="Output encoding.",
        choices={"base85", "base64", "base32", "base16", "uu"}
        if uu_encoding
        else {"base85", "base64", "base32", "base16"},
    )

    parser.add_argument(
        "--input-encoding",
        "--i-encoding",
        "-n",
        help="Input encoding.",
        choices={"base85", "base64", "base32", "base16", "uu"}
        if uu_encoding
        else {"base85", "base64", "base32", "base16"},
    )

    parser.add_argument(
        "--rounds", "-r", type=int, help="RC6 rounds", default=20
    )
    parser.add_argument(
        "--w-bit", "-b", type=int, help="RC6 w-bit", default=32
    )
    parser.add_argument(
        "--iv",
        "-I",
        help=(
            "IV for CBC mode only, for decryption"
            " if IV is not set the 16 first bytes are used instead."
        ),
    )
    parser.add_argument("--lgw", "-l", type=int, help="RC6 lgw", default=5)

    parser.add_argument(
        "--sha256",
        help="Use the sha256 hash of the key as the key.",
        action=BooleanOptionalAction,
        default=True,
    )
    parser.add_argument("key", help="Encryption key.")

    arguments = parser.parse_args()

    if arguments.input_file is None:
        arguments.input_file = stdin

    return arguments


def output_encoding(data: bytes, arguments: Namespace) -> bytes:
    """
    This function returns encoded data.
    """

    if arguments.base85 or arguments.output_encoding == "base85":
        encoding = b85encode
    elif arguments.base64 or arguments.output_encoding == "base64":
        encoding = b64encode
    elif arguments.base32 or arguments.output_encoding == "base32":
        encoding = b32encode
    elif arguments.base16 or arguments.output_encoding == "base16":
        encoding = b16encode
    elif uu_encoding and (arguments.uu or arguments.output_encoding == "uu"):
        simplefilter("ignore")
        data = b2a_hqx(data)
        simplefilter("default")
        return data
    else:
        raise ValueError("Invalid encoding algorithm value")

    return encoding(data)


def input_encoding(data: bytes, encoding: str) -> bytes:
    """
    This function returns decoded data.
    """

    if encoding == "base85":
        decoding = b85decode
    elif encoding == "base64":
        decoding = b64decode
    elif encoding == "base32":
        decoding = b32decode
    elif encoding == "base16":
        decoding = b16decode
    elif uu_encoding and encoding == "uu":
        simplefilter("ignore")
        data = a2b_hqx(data)
        simplefilter("default")
        return data
    else:
        raise ValueError("Invalid encoding algorithm value")

    return decoding(data)


def get_key(arguments: Namespace) -> bytes:
    """
    This function returns the key (256 bits) using sha256
    by default or PKCS 5/7 for padding.
    """

    if arguments.sha256:
        return sha256(arguments.key.encode()).digest()
    else:
        return pkcs5_7padding(arguments.key.encode(), 16)[:16]


def get_data(arguments: Namespace) -> bytes:
    """
    This function returns data for encryption from arguments.
    """

    if arguments.input_string:
        data = arguments.input_string
    else:
        data = arguments.input_file.read()

    if arguments.input_encoding:
        data = input_encoding(data, arguments.input_encoding)

    return data


def get_encodings():
    """
    This function returns the probable encodings.
    """

    encoding = getpreferredencoding()
    if encoding is not None:
        yield encoding

    encoding = device_encoding(0)
    if encoding is not None:
        yield encoding

    yield "utf-8"  # Default for Linux
    yield "cp1252"  # Default for Windows
    yield "latin-1"  # Can read all files


def decode_output(data: bytes) -> str:
    """
    This function decode outputs (try somes encoding).
    """

    output = None
    for encoding in get_encodings():
        with suppress(UnicodeDecodeError):
            output = data.decode(encoding)
            return output


def main() -> int:
    """
    This function executes this file from the command line.
    """

    arguments = parse_args()

    if arguments.input_string:
        arguments.input_string = arguments.input_string.encode("utf-8")

    rc6 = RC6Encryption(
        get_key(arguments), arguments.rounds, arguments.w_bit, arguments.lgw
    )
    format_output = any(
        [
            arguments.base85,
            arguments.base64,
            arguments.base32,
            arguments.base16,
            arguments.uu if uu_encoding else None,
            arguments.output_encoding,
        ]
    )

    if arguments.mode == "ECB":
        function = (
            rc6.data_decryption_ECB
            if arguments.decryption
            else rc6.data_encryption_ECB
        )
        data = function(get_data(arguments))
    elif arguments.mode == "CBC":
        function = (
            rc6.data_decryption_CBC
            if arguments.decryption
            else rc6.data_encryption_CBC
        )
        if arguments.decryption and not arguments.iv:
            data = get_data(arguments)
            iv = data[:16]
            data = data[16:]
        else:
            iv = arguments.iv.encode()
            data = get_data(arguments)

        data = function(data, iv)

        if isinstance(data, tuple):
            data = b"".join(data)

    if format_output:
        data = output_encoding(data, arguments)

    arguments.output_file.write(data)
    return 0


if __name__ == "__main__":
    exit(main())
