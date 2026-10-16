
from shamir_mnemonic import generate_mnemonics, combine_mnemonics


class ShamirManager:

    @staticmethod
    def split_secret(secret: bytes, threshold: int, total: int):
        if threshold < 2:
            raise ValueError("Invalid threshold or total")

        if threshold > total:
            raise ValueError("Invalid threshold or total")

        if total > 16:
            raise ValueError("Invalid threshold or total")

        group_threshold = 1
        group_settings = [(threshold, total)]

        groups = generate_mnemonics(
            group_threshold=group_threshold,
            groups=group_settings,
            master_secret=secret
        )

        shares = groups[0]
        return shares

    @staticmethod
    def recover_secret(shares):
        recovered_secret = combine_mnemonics(shares)
        return recovered_secret
