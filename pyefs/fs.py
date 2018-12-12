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
    def __init__(self, user, owner, server, raw_name, path='', parent=None,
                 data=b''):
        super().__init__(user, server, raw_name, path)

        self.owner  = owner
        self.parent = parent
        self.fpr = FilePermissionRecord(user, owner, server, raw_name, path)
        self.write(data)

    def write(self, data=b''):
        perm_block = self.fpr.get_perms()
        if not (perm_block and perm_block.has_write):
            return

        k_w = perm_block.k_w
        self._write(AES_HMAC(k_w).encrypt(data))

    def read(self):
        perm_block = self.fpr.get_perms()
        if not perm_block:
            return

        k_r = perm_block.k_r
        return AES_HMAC(k_r).decrypt(self._read())

class FilePermissionRecord(FileSystemObject):
    def __init__(self, user, owner, server, raw_name, path=''):
        super().__init__(user, server, raw_name, path)
        self.owner = owner

        # Mapping of public keys to pickled + encrypted FilePermBlocks.
        self.perm_blocks = dict()
        self.ro_copies = []

        self.cached = dict()

        if self.exists():
            self._load()
        else:
            # Ignoring exact details of the encryption schemes for now, but
            # the idea will be to generate these keys here and initialize
            # an AES_HMAC with the key when we want to encrypt/decrypt.
            k_r, k_w = keygen(), keygen()
            # Similar idea here once we implement PK crypto.
            sk_f = pk_keygen()[0]

            fileptr = NameGenerator.random_filename()

            owner_block = FilePermBlock('', owner, k_r, k_w, sk_f, fileptr)
            self.add_perm(owner_block)

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
            print('error: only a file\'s owner can modify its permissions',
                  file=sys.stderr)
            return

        data = {'record': fpr_bytes, 'signature': signature}
        self._write(pickle.dumps(data))

    def _load(self):
        data = pickle.loads(self.server.read_file(self.raw_name))
        fpr_bytes = data['record']
        signature = data['signature']
        if not self.user.verify(self.owner, fpr_bytes, signature):
            print('error: FPR signature is invalid', file=sys.stderr)
        self.owner       = fpr_bytes['owner']
        self.perm_blocks = fpr_bytes['perm_blocks']
        self.ro_copies   = fpr_bytes['ro_copies']

    def get_perms(self):
        '''Returns the decrypted permission block at the current user's
        public key if there is one and the user can decrypt it. Otherwise,
        returns None.
        '''
        encrypted_block = self.perm_blocks.get(self.user.public_key())
        if encrypted_block is None:
            print('error: user has no permissions', file=sys.stderr)
            return None
        try:
            perm_block = pickle.loads(self.user.decrypt(encrypted_block))
        except pickle.UnpicklingError:
            print('error: permission block decrypted incorrectly',
                  file=sys.stderr)
            return None
        return perm_block

    def add_perm(self, perm_block):
        '''Encrypts and stores a permission block provided by the owner of
        the file.
        '''
        # self._flush() will make sure of this anyways, but no need to do the
        # extra work of pickling and encrypting to find out.
        if self.user.public_key() != self.owner:
            print('error: only the owner can change a file\'s permissions',
                  file=sys.stderr)
            return
        encrypted_block = self.user.encrypt(pickle.dumps(perm_block))
        self.perm_blocks[self.owner] = encrypted_block
        self._flush()

    def get_file(self):
        # Index into permission blocks with this user's pk.
        perm_block = self.get_perms()
        if perm_block is None:
            return None

        if perm_block.fileptr in cached:
            return cached[perm_block.fileptr]
        else:
            f = File(self.user, self.owner, self.server, perm_block.fileptr,
                     self.path, os.path.split(src.rstrip('/'))[0])
            cached[perm_block.fileptr] = f
            return f

class FilePermBlock:
    def __init__(self, username, pk, k_r, k_w, sk_f, fileptr):
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
        f = File(self.user, self.user.public_key(), self.server, raw_name,
                self.path + '/' + name)
        self[name] = f.fpr
