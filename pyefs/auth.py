from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC, RSA
from Crypto.Signature import DSS

from .aes_hmac import AES_HMAC
from .conf import SECURITY_PARAM, AES_KEY_SZ


def encrypt_keygen(ks=None):
    if ks is None:
        ks = SECURITY_PARAM * 8

    return RSA.generate(ks)

def sign_keygen():
    return ECC.generate(curve='P-256')

def sym_keygen():
    return Random.new().read(AES_KEY_SZ)


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

    def encrypt(self, data, pk=None):
        '''Encrypt the data using the given public key, or if no public key
        is given, using the user's public key.
        '''
        if pk is None:
            return PKCS1_OAEP.new(self.asym_ae).encrypt(data)
        return PKCS1_OAEP.new(pk).encrypt(data)
    def decrypt(self, data):
        '''Decrypt the data using the user's secret key.'''
        return PKCS1_OAEP.new(self.asym_ae).decrypt(data)

    def sign(self, data):
        '''Sign the data using the user's secret key and return the signature.
        '''
        h = SHA256.new(data)
        signer = DSS.new(self.asym_sign, 'fips-186-3')
        return signer.sign(h)
    def verify(self, data, signature, pk=None):
        '''Verify the signature on the data using the given public key, or if
        no public key is given, the user's public key.
        '''
        h = SHA256.new(data)
        if pk is None:
            verifier = DSS.new(self.asym_sign, 'fips-186-3')
        else:
            verifier = DSS.new(pk, 'fips-186-3')
        try:
            verifier.verify(h, signature)
        except ValueError:
            return False
        return True

    def public_key(self):
        '''Return the user's ECDSA public key.'''
        return self.asym_sign.public_key().export_key(format="PEM")
