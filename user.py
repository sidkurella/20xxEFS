import collections
import json
import os
import os.path
import pickle

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA, ECC

from pyefs.auth import UserAuth, encrypt_keygen, sign_keygen, sym_keygen
from pyefs.name_gen import NameGenerator

class User:
    @staticmethod
    def parse(data):
        return pickle.loads(data)

    @staticmethod
    def generate(username, ks=None):
        rsa_key = encrypt_keygen(ks)
        rsa_pub = rsa_key.publickey()

        dsa_key = sign_keygen()
        dsa_pub = dsa_key.public_key()

        return User(
            username = username,
            sym_k    = sym_keygen(),
            asym_pk  = rsa_pub.export_key(),
            asym_sk  = rsa_key.export_key(),
            sign_pk  = dsa_pub.export_key(format="PEM"),
            sign_sk  = dsa_key.export_key(format="PEM"),
            root     = NameGenerator.random_filename()
        )

    def __init__(self,
                 username=None,
                 sym_k=None,
                 asym_pk=None, asym_sk=None,
                 sign_pk=None, sign_sk=None,
                 root=None):
        self.username = username
        self.sym_k    = sym_k
        self.asym_pk  = asym_pk
        self.asym_sk  = asym_sk
        self.sign_pk  = sign_pk
        self.sign_sk  = sign_sk
        self.root     = root

    def auth(self):
        return UserAuth.default(
            self.username,
            self.sym_k,
            (self.asym_pk, self.asym_sk),
            (self.sign_pk, self.sign_sk)
        )

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

    def get_user_public(self, name):
        private_user = self.get_user(name)

        return User(asym_pk=private_user.asym_pk, sign_pk=private_user.sign_pk)

    def add_user(self, name, user):
        with open(self._get_user_file(name), 'wb') as f:
            f.write(user.format())
