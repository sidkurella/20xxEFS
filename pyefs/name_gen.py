import secrets

DEFAULT_FILE_SZ = 32

class NameGenerator:
    @staticmethod
    def random_filename(sz=DEFAULT_FILE_SZ):
        return secrets.token_hex(sz)
