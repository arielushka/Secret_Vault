"""Shamir sharing through PyCryptodome, with legacy share recovery."""

import base64
import binascii

from Crypto.Protocol.SecretSharing import Shamir


class ShamirManager:
    @staticmethod
    def split_secret(secret: bytes, threshold: int, total: int):
        if len(secret) != 16 or not 2 <= threshold <= total <= 16:
            raise ValueError("Invalid secret, threshold, or total")
        return [
            base64.b64encode(bytes([index]) + share).decode("ascii")
            for index, share in Shamir.split(threshold, total, secret)
        ]

    @staticmethod
    def recover_secret(shares):
        try:
            decoded = [base64.b64decode(share, validate=True) for share in shares]
            if all(len(share) == 17 and 1 <= share[0] <= 16 for share in decoded):
                return Shamir.combine([(share[0], share[1:]) for share in decoded])
        except (ValueError, binascii.Error):
            pass

        # Existing uploads use SLIP-0039 mnemonic shares; keep them readable.
        try:
            from shamir_mnemonic import combine_mnemonics
        except ImportError as error:
            raise ValueError("Install requirements-legacy.txt to open old files") from error

        return combine_mnemonics(shares)
