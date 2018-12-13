import pickle

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
        asym_sk = asym_k[1] if asym_k[1] is not None else asym_k[0]
        sign_sk = sign_k[1] if sign_k[1] is not None else sign_k[0]
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

    def hybrid_encrypt(self, data, pk=None):
        # Use hybrid encryption to encrypt the permission block, since it will
        # be too long to encrypt with just the public key scheme.
        key = sym_keygen()
        encrypted_key = self.encrypt(key, pk)
        encrypted_block = AES_HMAC(key).encrypt(pickle.dumps(data))

        return pickle.dumps({
            'encrypted_key': encrypted_key,
            'encrypted_block': encrypted_block
        })

    def hybrid_decrypt(self, data):
        hybrid_encrypted = pickle.loads(data)

        encrypted_key   = hybrid_encrypted['encrypted_key']
        encrypted_block = hybrid_encrypted['encrypted_block']

        # First, we need to decrypt the encrypted key using this user's
        # secret key.
        key = self.decrypt(encrypted_key)

        # Next, we can read the block by decrypting it with the newly
        # decrypted symmetric key.
        try:
            return pickle.loads(AES_HMAC(key).decrypt(encrypted_block))
        except pickle.UnpicklingError:
            raise ValueError('hybrid decrypted incorrectly')

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
