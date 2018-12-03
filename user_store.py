import base64
import collections
import json
import os
import os.path

class UserStore:
    def __init__(self, path):
        self.path = os.path.abspath(path)
        self.cache = dict()

        if not os.path.isdir(self.path):
            os.makedirs(self.path)

    def _get_user_file(self, name):
        return os.path.join(self.path, name)
    def _get_user_kvs(self, name):
        if name not in self.cache:
            with open(self._get_user_file(name), 'r') as f:
                self.cache[name] = { k: base64.b64decode(v) for k, v in json.load(f).items() }
        return self.cache[name]

    def get_user_sym_k(self, name):
        return self._get_user_kvs(name)['sym_k']

    def get_user_asym_pk(self, name):
        return self._get_user_kvs(name)['asym_pk']
    def get_user_asym_sk(self, name):
        return self._get_user_kvs(name)['asym_sk']

    def get_user_sign_pk(self, name):
        return self._get_user_kvs(name)['sign_pk']
    def get_user_sign_sk(self, name):
        return self._get_user_kvs(name)['sign_sk']

    def get_user_root_dir(self, name):
        return self._get_user_kvs(name)['root_dir']

    def add_user(self, name, s):
        s_b64 = {k: base64.b64encode(v).decode('ascii') for k, v in s.items()}
        with open(self._get_user_file(name), 'w') as f:
            json.dump(s_b64, f)
