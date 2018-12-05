import os.path
import pickle

from .aes_hmac import AES_HMAC

class FilesystemObject:
    def __init__(self, disk_name, server):
        self.disk_name = disk_name
        self.server = server

    def get_listing(self):
        return self.disk_name

class Directory(FilesystemObject):
    def __init__(self, disk_name, server, key, parent=None):
        super().__init__(disk_name, server)
        self.key = key # Owner's symmetric encryption key
        self.aes_hmac = AES_HMAC(key)

        # Parent's listing. Ignored if already present.
        self.parent = parent

        self.load()

    def __iter__(self):
        return self.entries.__iter__()

    def load(self):
        if not self.server.has_file(self.disk_name):
            self.entries = dict()
            self.flush()
        else:
            data = self.server.read_file(self.disk_name)
            data = self.aes_hmac.decrypt(data)

            self.parent, self.entries = pickle.loads(data)

    def flush(self):
        data = pickle.dumps((self.parent, self.entries))
        data = self.aes_hmac.encrypt(data)
        self.server.write_file(self.disk_name, data)

    def has_entry(self, filename):
        return filename in self.entries

    def add_entry(self, filename, listing):
        self.entries[filename] = listing
        self.flush()

    def rm_entry(self, filename):
        del self.entries[filename]
        self.flush()

    def get(self, key, default=None):
        return self.entries.get(key, default)

class FileMetadata(FilesystemObject):
    @staticmethod
    def load(server, disk_name):
        return pickle.loads(server.read_file(disk_name))

    def __init__(self, disk_name, server, owner_pk):
        super().__init__(disk_name, server)
        self.perm_blocks = dict()
        self.owner_pk = owner_pk

    def add_perm(self, username, pk, has_write):
        pass

class FilePermBlock:
    def __init__(self, username, pk, k_r, k_w, sk_f, contents):
        if k_w is None or sk_f is None:
            self.has_write = False
        else:
            self.has_write = True

        self.username = username
        self.user_pk = pk # Key to encrypt the perm block under.
        self.k_r = k_r # Read key.
        self.k_w = k_w # Write key.
        self.sk_f = sk_f # File signing key.
        self.contents = contents # Disk name of file contents.

