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
        self.fpr = FilePermissionRecord(user, owner, server, raw_name, path)

    def add_perm(self, username, pk, has_write):
        pass

class FilePermissionRecord(FileSystemObject):
    def __init__(self, user, owner, server, raw_name, path=''):
        super().__init__(user, server, raw_name, path)
        self.owner = owner

        self.perm_blocks = dict()
        self.ro_copies = []

    def _flush(self):
        fpr_bytes = pickle.dumps({
            'owner': self.owner,
            'perm_blocks': self.perm_blocks,
            'ro_copies': ro_copies
        })
        # sign with user's dig sig sk, which should be the owner's sk. if it
        # doesn't verify with the owner's pk, don't flush.
        signature = self.user.sign(fpr_bytes)
        # TODO The sign and verify methods should be separate from the UserAuth
        # class.
        if not self.user.verify(self.owner, fpr_bytes, signature):
            print('error: only a file\'s owner can modify its perrmissions')

        data = {'record': fpr_bytes, 'signature': signature}
        self._write(pickle.dumps(data))

    def _load(self):
        if self.exists():
            data = pickle.loads(self.server.read_file(self.raw_name))
            fpr_bytes = data['record']
            signature = data['signature']
            if not self.user.verify(self.owner, fpr_bytes, signature):
                print('error: file corrupted, FPR signature is invalid')
            self.owner       = fpr_bytes['owner']
            self.perm_blocks = fpr_bytes['perm_blocks']
            self.ro_copies   = fpr_bytes['ro_copies']

class FilePermBlock:
    def __init__(self, username, pk, k_r, k_w, sk_f, contents):
        if k_w is None or sk_f is None:
            self.has_write = False
        else:
            self.has_write = True

        # TODO no reason for the first two fields here, right?
        self.username = username
        self.user_pk = pk          # Key to encrypt the perm block under.
        self.k_r = k_r             # Read key.
        self.k_w = k_w             # Write key.
        self.sk_f = sk_f           # File signing key.
        self.fileptr = fileptr     # Raw name of file associated with this
                                   # block. If self.has_write = True, then this
                                   # is the raw name of the main copy of the
                                   # file, otherwise it's a pointer to a
                                   # read-only copy specific to the user.

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
            return FilePermissionRecord(self.user, item[0], self.server,
                                        item[1], self._path + '/' + name, self)
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
            if isinstance(listing, FilePermissionRecord):
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
