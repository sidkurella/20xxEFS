
from .aes_hmac import AES_HMAC

class UserAuth:
    @staticmethod
    def default(name, sym_k, asym_k, sign_k):
        return UserAuth(name, AES_HMAC(sym_k), None, None)

    def __init__(self, name, sym_ae, asym_ae, asym_sign):
        self.name      = name
        self.sym_ae    = sym_ae
        self.asym_ae   = asym_ae
        self.asym_sign = asym_sign

    def encrypt_symmetric(self, data):
        return self.sym_ae.encrypt(data)
    def decrypt_symmetric(self, data):
        return self.sym_ae.decrypt(data)

    def encrypt(self, data):
        pass
    def decrypt(self, data):
        pass
    def sign(self, data):
        pass
    def verify(self, data):
        pass
