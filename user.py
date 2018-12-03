import base64
import collections
import json
import os
import os.path

from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES

from pyefs.name_gen import NameGenerator
from pyefs.conf import SECURITY_PARAM

class User:
    @staticmethod
    def parse(kvs):
        return User(**kvs)

    @staticmethod
    def generate(ks=None):
        if ks is None:
            ks = SECURITY_PARAM * 8

        rsa_key = RSA.generate(ks)
        pub_key = rsa_key.publickey()

        return User(
            sym_k   = Random.new().read(AES.block_size),
            asym_pk = pub_key.export_key(),
            asym_sk = rsa_key.export_key(),
            sign_pk = pub_key.export_key(),
            sign_sk = rsa_key.export_key(),
            root    = NameGenerator.random_filename().encode('ascii')
        )

    def __init__(self,
                 sym_k=None,
                 asym_pk=None, asym_sk=None,
                 sign_pk=None, sign_sk=None,
                 root=None):
        self.sym_k   = sym_k
        self.asym_pk = asym_pk
        self.asym_sk = asym_sk
        self.sign_pk = sign_pk
        self.sign_sk = sign_sk
        self.root    = root

    def format(self):
        exports = [ 'sym_k', 'asym_pk', 'asym_sk', 'sign_pk', 'sign_sk', 'root' ]

        return { k: base64.b64encode(getattr(self, k)).decode('ascii')
                        for k in exports }

class UserStore:
    def __init__(self, path):
        self.path = os.path.abspath(path)
        self.cache = dict()

        if not os.path.isdir(self.path):
            os.makedirs(self.path)

    def _get_user_file(self, name):
        return os.path.join(self.path, name)
    def _get_user_kvs(self, name):
        with open(self._get_user_file(name), 'r') as f:
            return { k: base64.b64decode(v) for k, v in json.load(f).items() }

    def get_user(self, name):
        if name not in self.cache:
            self.cache[name] = User.parse(self._get_user_kvs(name))
        return self.cache[name]

    def add_user(self, name, user):
        with open(self._get_user_file(name), 'w') as f:
            json.dump(user.format(), f)
