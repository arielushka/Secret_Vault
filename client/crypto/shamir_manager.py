
from shamir_mnemonic import generate_mnemonics, combine_mnemonics


class ShamirManager:

    @staticmethod
    def split_secret(secret: bytes, threshold: int, total: int):
        # Any threshold-sized subset of the generated shares can recover the key.
        if threshold < 2:
            raise ValueError("Invalid threshold or total")

        if threshold > total:
            raise ValueError("Invalid threshold or total")

        if total > 16:
            raise ValueError("Invalid threshold or total")

        group_threshold = 1
        # One group contains all recipients; threshold controls how many shares are needed.
        group_settings = [(threshold, total)]

        groups = generate_mnemonics(
            group_threshold=group_threshold,
            groups=group_settings,
            master_secret=secret
        )

        shares = groups[0]
        # Return one encoded share for each recipient in the upload flow.
        return shares

    @staticmethod
    def recover_secret(shares):
        # The Shamir library validates and combines the supplied share phrases.
        recovered_secret = combine_mnemonics(shares)
        return recovered_secret
