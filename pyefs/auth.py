from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC, RSA
from Crypto.Signature import DSS

from .aes_hmac import AES_HMAC

class UserAuth:
    @staticmethod
    def default(name, sym_k, asym_k, sign_k):
        asym_sk, sign_sk = asym_k[1], sign_k[1]
        return UserAuth(
                name,
                sym_k,
                RSA.import_key(asym_sk),
                ECC.import_key(sign_sk)
        )

    def __init__(self, name, sym_ae, asym_ae, asym_sign):
        self.name      = name
        self.sym_ae    = sym_ae
        self.asym_ae   = asym_ae
        self.asym_sign = asym_sign

    def encrypt_symmetric(self, data):
        return AES_HMAC(self.sym_ae).encrypt(data)
    def decrypt_symmetric(self, data):
        return AES_HMAC(self.sym_ae).decrypt(data)

    def encrypt(self, data):
        return PKCS1_OAEP.new(self.asym_ae).encrypt(data)
    def decrypt(self, data):
        return PKCS1_OAEP.new(self.asym_ae).decrypt(data)

    def sign(self, data):
        h = SHA256.new(data)
        signer = DSS.new(self.asym_sign, 'fips-186-3')
        return signer.sign(h)
    def verify(self, data, signature):
        try:
            h = SHA256.new(data)
            verifier = DSS.new(self.asym_sign, 'fips-186-3')
            verifier.verify(h, signature)
            return True
        except ValueError:
            return False

    def public_key(self):
        return self.asym_ae.publickey().export_key()
