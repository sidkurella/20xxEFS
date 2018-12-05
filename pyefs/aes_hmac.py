import pickle

from Crypto.Hash import HMAC, SHA256
from Crypto.Cipher import AES
from Crypto import Random

from .conf import AES_KEY_SZ

class AES_HMAC:
    def __init__(self, key):
        if len(key) != AES_KEY_SZ:
            raise ValueError('Key is not of AES block size ({})'.format(
                AES_KEY_SZ
            ))
        self.key = key

    def encrypt(self, plaintext):
        iv = Random.new().read(AES.block_size)
        aes = AES.new(self.key, AES.MODE_CBC, iv)
        hmac = HMAC.new(self.key, digestmod=SHA256)

        sz = len(plaintext)

        padding_bytes = (AES.block_size - (sz % AES.block_size))

        ciph = aes.encrypt(plaintext + padding_bytes * bytes([padding_bytes]))
        tag = hmac.update(ciph).digest()

        return pickle.dumps({
            'iv': iv,
            'ciphertext': ciph,
            'tag': tag
        })

    def decrypt(self, ciphertext):
        ciph = pickle.loads(ciphertext)

        aes = AES.new(self.key, AES.MODE_CBC, ciph['iv'])
        hmac = HMAC.new(self.key, digestmod=SHA256)

        if hmac.update(ciph['ciphertext']).digest() != ciph['tag']:
            raise ValueError('Tag does not match for {!r}'.format(ciph))

        raw_decrypt = aes.decrypt(ciph['ciphertext'])
        padding = raw_decrypt[-1]
        if padding not in range(1, AES.block_size + 1):
            raise ValueError('Invalid padding for {!r}'.format(ciph))
        if not all(x == padding for x in raw_decrypt[-padding:]):
            raise ValueError('Invalid padding for {!r}'.format(ciph))

        return raw_decrypt[:-padding]
