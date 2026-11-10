"""Split and recover AES keys with Shamir secret sharing."""

from Crypto.Protocol.SecretSharing import Shamir


class ShamirManager:
    @staticmethod
    def split_secret(secret: bytes, threshold: int, total: int):
        if len(secret) != 16 or not 2 <= threshold <= total <= 16:
            raise ValueError("Invalid secret, threshold, or total")
        return [bytes([index]) + share
                for index, share in Shamir.split(threshold, total, secret)]

    @staticmethod
    def recover_secret(shares):
        if not shares or any(
            not isinstance(share, bytes)
            or len(share) != 17
            or not 1 <= share[0] <= 16
            for share in shares
        ):
            raise ValueError("Invalid Shamir shares")
        return Shamir.combine([(share[0], share[1:]) for share in shares])
