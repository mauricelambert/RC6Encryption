#!/usr/bin/env python3
# -*- coding: utf-8 -*-

###################
#    This package implements RC6 encryption.
#    Copyright (C) 2021  Maurice Lambert

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


~# rc6 abcdefghijklmnop -s abcdefghijklmnop -6
bM4cLTYlcjp3dk1z7LgsJg==
~# rc6 abcdefghijklmnop -s bM4cLTYlcjp3dk1z7LgsJg== -n base64 -d
abcdefghijklmnop
~# rc6 abcdefghijklmnop --no-sha256 -r 12 -s abcdefghijklmnop -6
w08njgYKPqiXDUcZxw8z7g==
~# rc6 abcdefghijklmnop --no-sha256 -r 12 -s w08njgYKPqiXDUcZxw8z7g== -n base64 -d
abcdefghijklmnop
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

__version__ = "0.0.1"
__author__ = "Maurice Lambert"
__author_email__ = "mauricelambert434@gmail.com"
__maintainer__ = "Maurice Lambert"
__maintainer_email__ = "mauricelambert434@gmail.com"
__description__ = """This package implements RC6 encryption."""
license = "GPL-3.0 License"
__url__ = "https://github.com/mauricelambert/RC6Encryption"

copyright = """
RC6Encryption  Copyright (C) 2021  Maurice Lambert
This program comes with ABSOLUTELY NO WARRANTY.
This is free software, and you are welcome to redistribute it
under certain conditions.
"""
__license__ = license
__copyright__ = copyright

__all__ = ["RC6Encryption"]

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
from argparse import Namespace, ArgumentParser, FileType
from binascii import a2b_hqx, b2a_hqx
from collections.abc import Iterator
from typing import Tuple, List
from functools import partial
from hashlib import sha256
from io import BytesIO
import argparse
import warnings
import sys

basetwo = partial(int, base=2)
unblock = partial(int.to_bytes, length=4, byteorder="big")


class RC6Encryption:

    """
    This class implements the RC6 encryption.

    Rounds possible values: {12, 16, 20}
    """

    P32 = 0xB7E15163
    Q32 = 0x9E3779B9

    def __init__(self, key: bytes, rounds: int = 20, w_bit: int = 32, lgw: int = 5):
        self.key_bytes = key
        self.rounds = rounds
        self.w_bit = w_bit
        self.lgw = lgw

        self.round2_2 = rounds * 2 + 2
        self.round2_3 = self.round2_2 + 1
        self.round2_4 = self.round2_3 + 1

        self.modulo = 2 ** w_bit

        self.key_binary_blocks, self.key_integer_reverse_blocks = self.get_blocks(key)
        self.key_blocks_number = len(self.key_binary_blocks)

        self.key_integer_reverse_blocks.reverse()

        self.rc6_key = [self.P32]

        self.key_generation()

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
            block = f"{block}{bin(char)[2:]:0>8}"

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

        mask = (2 ** n) - 1
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
        v = (
            3 * self.key_blocks_number
            if self.key_blocks_number > self.round2_4
            else self.round2_4
        )

        for i_ in range(v):
            a = self.rc6_key[i] = self.left_rotation(
                (self.rc6_key[i] + a + b) % self.modulo, 3
            )
            b = self.key_integer_reverse_blocks[j] = self.left_rotation(
                (self.key_integer_reverse_blocks[j] + a + b) % self.modulo, (a + b) % 32
            )
            i = (i + 1) % (self.round2_4)
            j = (j + 1) % self.key_blocks_number

        return self.rc6_key

    def encrypt(self, data: bytes) -> List[int]:

        """
        This functions performs RC6 encryption.

        This function returns a list of 4 integers.
        """

        _, data = self.get_blocks(data)
        a, b, c, d = data

        b = (b + self.rc6_key[0]) % self.modulo
        d = (d + self.rc6_key[1]) % self.modulo

        for i in range(1, self.rounds + 1):
            t = self.left_rotation(b * (2 * b + 1) % self.modulo, self.lgw)
            u = self.left_rotation(d * (2 * d + 1) % self.modulo, self.lgw)
            tmod = t % self.w_bit
            umod = u % self.w_bit
            a = (self.left_rotation(a ^ t, umod) + self.rc6_key[2 * i]) % self.modulo
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
                self.right_rotation((c - self.rc6_key[2 * i + 1]) % self.modulo, tmod)
                ^ u
            )
            a = self.right_rotation((a - self.rc6_key[2 * i]) % self.modulo, umod) ^ t

        d = (d - self.rc6_key[1]) % self.modulo
        b = (b - self.rc6_key[0]) % self.modulo

        return [a, b, c, d]


def get_sized_data(data: bytes, size: int = 16) -> bytes:

    """
    This function return sized data.
    """

    mod = len(data) % size
    if mod:
        data = data + b"\x00" * (size - mod)

    return data


def parse_args() -> Namespace:

    """
    This function parse command line arguments.
    """

    parser = ArgumentParser(description="This file performs RC6 encryption.")

    parser.add_argument(
        "--decryption", "-d", help="Data decryption.", action="store_true"
    )

    input_ = parser.add_mutually_exclusive_group(required=True)
    input_.add_argument(
        "--input-file",
        "--i-file",
        "-i",
        type=FileType("rb"),
        default=sys.stdin,
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
        type=FileType("w", encoding="latin-1"),
        default=sys.stdout,
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
    output_encoding.add_argument(
        "--uu", "-u", help="UU encoding as output format", action="store_true"
    )
    output_encoding.add_argument(
        "--output-encoding",
        "--o-encoding",
        "-e",
        help="Output encoding.",
        choices={"base85", "base64", "base32", "base16", "uu"},
    )

    parser.add_argument(
        "--input-encoding",
        "--i-encoding",
        "-n",
        help="Input encoding.",
        choices={"base85", "base64", "base32", "base16", "uu"},
    )

    parser.add_argument("--rounds", "-r", type=int, help="RC6 rounds", default=20)
    parser.add_argument("--w-bit", "-b", type=int, help="RC6 w-bit", default=32)
    parser.add_argument("--lgw", "-l", type=int, help="RC6 lgw", default=5)

    parser.add_argument(
        "--sha256",
        help="Use the sha256 of the key as the key.",
        action=argparse.BooleanOptionalAction,
        default=True,
    )
    parser.add_argument("key", help="Encryption key.")

    arguments = parser.parse_args()

    if arguments.input_file is None:
        arguments.input_file = sys.stdin

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
    elif arguments.uu or arguments.output_encoding == "uu":
        warnings.simplefilter("ignore")
        data = b2a_hqx(data)
        warnings.simplefilter("default")
        return data

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
    elif encoding == "uu":
        warnings.simplefilter("ignore")
        data = a2b_hqx(data)
        warnings.simplefilter("default")
        return data

    return decoding(data)


def get_key(arguments: Namespace) -> bytes:

    """
    This function returns the key (256 bits).
    """

    if arguments.sha256:
        return sha256(arguments.key.encode()).digest()
    else:
        return get_sized_data(arguments.key.encode(), 16)


def generator_data(data: bytes, encoding: str) -> Iterator[bytes]:

    """
    Generator to return encoded data for encryption.
    """

    if encoding:
        data = input_encoding(data, encoding)

    for i in range(0, len(data), 16):
        temp = data[i : i + 16]
        if temp:
            yield get_sized_data(temp)


def get_data(arguments: Namespace) -> Iterator[bytes]:

    """
    Generator to return data for encryption.
    """

    if arguments.input_string:
        yield from generator_data(arguments.input_string, arguments.input_encoding)
    elif arguments.input_encoding:
        yield from generator_data(arguments.input_file.read(), arguments.input_encoding)
    else:
        data = arguments.input_file.read(16)
        while data:
            if isinstance(data, str):
                data = data.encode("utf-8")
            yield get_sized_data(data)
            data = arguments.input_file.read(16)


def main() -> None:

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
            arguments.uu,
            arguments.output_encoding,
        ]
    )
    function = rc6.decrypt if arguments.decryption else rc6.encrypt
    buffer = BytesIO()

    for data in get_data(arguments):
        data = rc6.blocks_to_data(function(data))

        if format_output:
            buffer.write(data)
        else:
            arguments.output_file.write(data.decode("latin-1"))

    if format_output:
        buffer.seek(0)
        arguments.output_file.write(
            output_encoding(buffer.read(), arguments).decode("latin-1")
        )


if __name__ == "__main__":
    main()
    sys.exit(0)
