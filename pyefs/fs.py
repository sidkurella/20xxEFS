import os.path
import pickle

from .aes_hmac import AES_HMAC
from .name_gen import NameGenerator

class FilesystemObject:
    def __init__(self, user, server, raw_name, path):
        self.user     = user
        self.server   = server
        self.raw_name = raw_name
        self._path    = path

    def exists(self):
        return self.server.has_file(self.raw_name)
    def _read(self):
        return self.server.read_file(self.raw_name)
    def _write(self, data):
        self.server.write_file(self.raw_name, data)
    def delete(self):
        self.server.remove_file(self.raw_name)

    @property
    def path(self):
        if self._path == '':
            return '/'
        return self._path

class File(FilesystemObject):
    def __init__(self, user, owner, server, raw_name, path='', parent=None):
        super().__init__(user, server, raw_name, path)

        self.owner  = owner
        self.parent = parent

        self.perm_blocks = dict()
        self.ro_copies = []
        self.main_copy = None

    def add_perm(self, username, pk, has_write):
        pass

class FileContents(FilesystemObject):
    def get_hash(self):
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
        self.contents = contents # FileContents object.

    def serialize(self):
        pass

class Directory(FilesystemObject):
    def __init__(self, user, server, raw_name, path='', parent=None):
        super().__init__(user, server, raw_name, path)

        self.parent  = parent
        self.entries = dict()
        self.cached  = dict()
        self._load()

    def _load(self):
        if self.exists():
            data = self.server.read_file(self.raw_name)
            data = self.user.decrypt_symmetric(data)

            self.entries = pickle.loads(data)

    def _load_subitem(self, name):
        item = self.entries[name]

        if isinstance(item, tuple):
            return File(self.user, item[0], self.server, item[1],
                    self._path + '/' + name, self)
        return Directory(self.user, self.server, item,
                self._path + '/' + name, self)

    def _flush(self):
        data = pickle.dumps(self.entries)
        data = self.user.encrypt_symmetric(data)
        self._write(data)

    def __len__(self):
        return len(self.entries)
    def __iter__(self):
        return iter(self.entries)

    def __contains__(self, name):
        return name in self.entries

    def __getitem__(self, name):
        if name not in self.cached:
            self.cached[name] = self._load_subitem(name)

        return self.cached[name]

    def __setitem__(self, name, listing):
        if name not in self.entries or listing != self.entries[name]:
            if isinstance(listing, File):
                self.entries[name] = (listing.owner, listing.raw_name)
                self.cached[name]  = listing
            elif isinstance(listing, Directory):
                self.entries[name] = listing.raw_name
                self.cached[name]  = listing
            else:
                raise ValueError('invalid listing type')

            self._flush()

    def __delitem__(self, name):
        del self.entries[name]
        self._flush()

    def get(self, key, default=None):
        if key not in self.entries:
            return default
        return self[key]

    def mkdir(self, name):
        raw_name = NameGenerator.random_filename()
        directory = Directory(self.user, self.server, raw_name,
                self.path + '/' + name)
        directory._flush()
        self[name] = directory

    def touch(self, name):
        raw_name = NameGenerator.random_filename()
        file = File(self.user, self.user.public_key(), self.server, raw_name,
                self.path + '/' + name)
        file._flush()
        self[name] = file
