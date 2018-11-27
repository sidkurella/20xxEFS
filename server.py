import base64
import collections
import json
import os.path

class Server:
    def __init__(self, path):
        self.path = path

        if not os.path.isfile(path):
            if os.path.exists(path):
                raise ValueError('path does not point to a file')

            self.kvs = dict()
            return

        with open(path, 'r') as fp:
            self.kvs = { k.encode('ascii'): base64.b64decode(v) for k, v in json.load(fp).items() }

    def has_file(self, name):
        return name in self.kvs
    def write_file(self, name, data):
        self.kvs[name] = data
    def read_file(self, name):
        return self.kvs[name]

    def flush(self):
        with open(self.path, 'w') as fp:
            json.dump({ k.decode('ascii'): base64.b64encode(v).decode('ascii') for k, v in self.kvs.items() }, fp)
