from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES

import json

from pyefs.name_gen import NameGenerator

DEFAULT_KEY_SZ = 2048

class UserFactory:
    @staticmethod
    def gen_user_keys(key_sz=DEFAULT_KEY_SZ):
        rsa_key = RSA.generate(key_sz)
        pub = rsa_key.publickey()
        s = {
            'sym_k': Random.new().read(AES.block_size),

            'asym_pk': pub.export_key(),
            'asym_sk': rsa_key.export_key(),

            'sign_pk': pub.export_key(),
            'sign_sk': rsa_key.export_key(),

            'root_dir': NameGenerator.random_filename()
        }

        return s
