import collections
import json
import os
import os.path
import pickle

from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES

from pyefs.name_gen import NameGenerator
from pyefs.conf import SECURITY_PARAM, AES_KEY_SZ

class User:
    @staticmethod
    def parse(data):
        return pickle.loads(data)

    @staticmethod
    def generate(ks=None):
        if ks is None:
            ks = SECURITY_PARAM * 8

        rsa_key = RSA.generate(ks)
        pub_key = rsa_key.publickey()

        return User(
            sym_k   = Random.new().read(AES_KEY_SZ),
            asym_pk = pub_key.export_key(),
            asym_sk = rsa_key.export_key(),
            sign_pk = pub_key.export_key(),
            sign_sk = rsa_key.export_key(),
            root    = NameGenerator.random_filename()
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
        return pickle.dumps(self)

class UserStore:
    def __init__(self, path):
        self.path = os.path.abspath(path)
        self.cache = dict()

        if not os.path.isdir(self.path):
            os.makedirs(self.path)

    def _get_user_file(self, name):
        return os.path.join(self.path, name)
    def _get_user_kvs(self, name):
        with open(self._get_user_file(name), 'rb') as f:
            return User.parse(f.read())

    def get_user(self, name):
        if name not in self.cache:
            self.cache[name] = self._get_user_kvs(name)
        return self.cache[name]

    def add_user(self, name, user):
        with open(self._get_user_file(name), 'wb') as f:
            f.write(user.format())
