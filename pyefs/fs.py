import os.path
import pickle
import traceback

from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA256

from .aes_hmac import AES_HMAC
from .auth import encrypt_keygen, sign_keygen, sym_keygen
from .conf import AES_KEY_SZ
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
    def __init__(self, user, perms, meta, server, raw_name, path=''):
        super().__init__(user, server, raw_name, path)

        self.perms = perms
        self.meta  = meta

    def write(self, data=b''):
        if not self.perms or not self.perms.can_write():
            raise ValueError('insufficient permissions to write file')

        encryption = AES_HMAC(self.perms.k_w).encrypt(data)
        self._write(encryption)

        copy_enc = AES_HMAC(self.perms.k_r).encrypt(data)
        for copy in self.meta.copies:
            self.server.write_file(copy, copy_enc)

        h = SHA256.new(data)
        self.meta.tag = DSS.new(ECC.import_key(self.perms.s_sk), 'fips-186-3').sign(h)
        self.meta._flush()

    def read(self):
        if not self.perms or not self.perms.can_read():
            raise ValueError('insufficient permissions to read file')

        key = self.perms.k_w if self.perms.can_write() else self.perms.k_r
        data = AES_HMAC(key).decrypt(self._read())

        h = SHA256.new(data)
        dss = DSS.new(ECC.import_key(self.perms.s_pk), 'fips-186-3')
        dss.verify(h, self.meta.tag)

        return data

class FileMetadata(FilesystemObject):
    def __init__(self, user, owner, server, raw_name, path='', parent=None):
        super().__init__(user, server, raw_name, path)

        self.owner  = owner
        self.parent = parent

        # Mapping of public keys to pickled + hybrid encrypted FilePermissions.
        self.perms  = dict()
        self.copies = []
        self.tag    = ''

        if self.exists():
            self._load()

    def _flush(self):
        perms = self.permissions()
        fpr_bytes = pickle.dumps({
            'owner':  self.owner,
            'perms':  self.perms,
            'copies': AES_HMAC(perms.k_w).encrypt(pickle.dumps(self.copies)),
            'tag':    self.tag
        })

        # Sign with user's dig sig sk, which should be the owner's sk.
        signature = self.user.sign(fpr_bytes)

        self._write(pickle.dumps({
            'record':    fpr_bytes,
            'signature': signature
        }))

    def _load(self):
        data = pickle.loads(self.server.read_file(self.raw_name))

        fpr_bytes = data['record']
        signature = data['signature']

        fpr = pickle.loads(fpr_bytes)
        self.owner = fpr['owner']
        self.perms = fpr['perms']
        self.tag   = fpr['tag']

        perms = self.permissions()
        if perms.can_write():
            self.copies = pickle.loads(AES_HMAC(perms.k_w).decrypt(fpr['copies']))

    def permissions(self):
        '''Returns the decrypted permission block at the current user's
           public key if there is one and the user can decrypt it. Otherwise,
           returns None. '''

        pk = self.user.public_key()
        if pk not in self.perms:
            return None

        return self.user.hybrid_decrypt(self.perms[pk])

    def file(self):
        # Index into permission blocks with this user's pk.
        perms = self.permissions()
        if perms is not None:
            return File(self.user, perms, self, self.server, perms.fileptr, self.path)

    def grant(self, user, writable=False):
        '''Encrypts and stores a permission block for the provided user with
           read or write permissions. '''
        self_pk = self.user.public_key()
        if self_pk != self.owner:
            raise ValueError('only the owner can change a file\'s permissions')

        user_pk = user.public_key()
        if user_pk in self.perms:
            raise ValueError('user already exists in permissions')

        if user_pk == self.owner:
            k_r = sym_keygen()
            k_w = sym_keygen()

            s_key = sign_keygen()
            s_sk = s_key.export_key(format="PEM")
            s_pk = s_key.public_key().export_key(format="PEM")
            fileptr = NameGenerator.random_filename()
        else:
            owner_fp = self.permissions()

            k_r = owner_fp.k_r
            k_w = owner_fp.k_w if writable else None
            s_pk = owner_fp.s_pk
            s_sk = owner_fp.s_sk if writable else None
            fileptr = owner_fp.fileptr

            if not writable:
                fileptr = NameGenerator.random_filename()
                self.copies.append(fileptr)

                data = self.file().read()
                encryption = AES_HMAC(k_r).encrypt(data)
                self.server.write_file(fileptr, encryption)

        perms = FilePermission(k_r, k_w, s_pk, s_sk, fileptr)
        self.perms[user_pk] = user.hybrid_encrypt(perms)

        self._flush()

class FilePermission:
    def __init__(self, k_r, k_w, s_pk, s_sk, fileptr):
        self.k_r = k_r             # Read key.
        self.k_w = k_w             # Write key.
        self.s_pk = s_pk           # File signing public key.
        self.s_sk = s_sk           # File signing private key.
        self.fileptr = fileptr     # Raw name of file associated with this
                                   # block. If self.has_write = True, then this
                                   # is the raw name of the main copy of the
                                   # file, otherwise it's a pointer to a
                                   # read-only copy specific to the user.

    def can_read(self):
        return self.k_r is not None
    def can_write(self):
        return self.k_r is not None and self.k_w is not None

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
            return FileMetadata(
                    self.user,
                    item[0],
                    self.server,
                    item[1],
                    self._path + '/' + name + '.fpr',
                    self
            )
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
            if isinstance(listing, FileMetadata):
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

        f = FileMetadata(self.user, self.user.public_key(), self.server, raw_name,
                self.path + '/' + name, self)

        self[name] = f

    def receive(self, name, raw_name, pk):
        f = FileMetadata(self.user, pk, self.server, raw_name,
                self.path + '/' + name, self)

        self[name] = f
