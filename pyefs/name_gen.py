import secrets

from .conf import SECURITY_PARAM_BYTES

class NameGenerator:
    @staticmethod
    def random_filename(sz=None):
        if sz is None:
            sz = SECURITY_PARAM_BYTES

        return secrets.token_hex(sz)
