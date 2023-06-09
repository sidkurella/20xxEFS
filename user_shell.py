#!/bin/env python3

import base64
import cmd
import inspect
import json
import os.path
import shlex
from itertools import zip_longest

from server import Server
from user import User, UserStore

from pyefs.auth import UserAuth
from pyefs.fs import Directory, File
from pyefs.name_gen import NameGenerator
from pyefs.aes_hmac import AES_HMAC

class UserRepl(cmd.Cmd):
    intro  = 'Welcome to the User REPL. Type help or ? for command help.'
    prompt = 'user> '

    def __init__(self, path, user_path, username):
        super().__init__()
        self.server = Server(path)
        self.user_store = UserStore(user_path)
        self.username = username

        try:
            self.user = self.user_store.get_user(username)
        except FileNotFoundError:
            print('INFO: generating new user {}'.format(username))

            self.user = User.generate()
            self.user_store.add_user(username, self.user)

        # Create auth for user
        self.auth = UserAuth.default(username, self.user.sym_k, None, None)

        # Start at the root directory.
        self.root    = Directory(self.auth, self.server, self.user.root)
        self.cur_dir = self.root

        # Run postcommand setup
        self.postcmd(False, None)


    def _getpath(self, path):
        current = self.cur_dir

        if path is None or path == '':
            return current

        comps = path.split('/')

        if comps[0] == '':
            current = self.root

        for name in comps:
            if name != '':
                if name == '..':
                    if current.parent is not None:
                        current = current.parent
                elif name in current:
                    current = current[name]
                else:
                    return None

        return current

    def postcmd(self, stop, line):
        self.prompt = '{} $ {}> '.format(self.username, self.cur_dir.path)
        return stop

    def do_help(self, argline):
        print('Welcome to the User REPL. Type any of these commands to get')
        print('more detailed command information.')
        for k, v in inspect.getmembers(self, predicate=inspect.ismethod):
            if k.startswith('do_'):
                name = k[3:]
                if name not in [ 'EOF' ]:
                    if v.__doc__ is None:
                        doc = '<no docstring>'
                    else:
                        lines = [ l.strip() for l in v.__doc__.split('\n') ]
                        doc = '\n'.join([lines[0]] +
                                [ '{}{}'.format(' ' * (2 + 12 + 3), l) for l in lines[1:]])

                    print('  {:>12} - {}'.format(name, doc))

    def do_pwd(self, argline):
        """ Prints the current working directory. """
        print(self.cur_dir.path)

    def do_cd(self, argline):
        """ Changes the current working directory. """
        args = shlex.split(argline)

        if len(args) > 1:
            print('usage: cd <dir_name>')
            return

        new_dir = self.cur_dir

        if len(args) == 0:
            new_dir = self.root
        elif args[0] == '-':
            new_dir = self.old_dir
        else:
            new_dir = self._getpath(args[0])

        if new_dir is None:
            print('{}: no such directory'.format(args[0]))
            return

        self.old_dir = self.cur_dir
        self.cur_dir = new_dir

    def do_read(self, argline):
        """Reads an encrypted file from the server to the user's local machine,
        provided that they're allowed to do this."""
        args = shlex.split(argline)

        if len(args) != 2:
            print('usage: read <src> <dst>')
            return

        src, dst = args[0], args[1]
        (head, tail) = os.path.split(src.rstrip('/'))

        if tail == '':
            raise ValueError('should never occur')

        parent_dir = self._getpath(head)

        if parent_dir is None or tail not in parent_dir:
            print('{}: file not found'.format(src))
            return

        # The directory entry gives us the file permission record.
        fpr = parent_dir[tail]
        # It should contain a permission block for this user encrypted under
        # their public key.
        # TODO implement user.public_key() (preferably something that accounts
        # for having different pks for dig sig and encryption schemes)
        encrypted_block = fpr.perm_blocks.get(self.user.public_key())
        if encrypted_block is None:
            print('error: can\'t access file without read permissions')
        perm_block = pickle.loads(self.user.decrypt(encrypted_block))
        # The permission block will contain the location of the actual file
        # along with the key we need to decrypt it.
        srcfile = perm_block.fileptr
        k_r = perm_block.k_r
        plaintext = AES_HMAC(k_r).decrypt(self.server.read_file(srcfile))

        try:
            with open(dst, 'wb') as f:
                f.write(plaintext)
        except OSError:
            print('error: could not write to {}'.format(dst))

    def do_write(self, argline):
        """Writes a plaintext file from the user's local machine to the server,
        encrypting it in the process. If the file doesn't already exist on the
        server, this will create a new file and make the user its owner. If it
        does exist, its permissions will dictate whether the user can write to
        it or not.
        """
        args = shlex.split(argline)

        if len(args) != 2:
            print('usage: write <src> <dst>')
            return

        src, dst = args[0], args[1]
        (head, tail) = os.path.split(dst.rstrip('/'))

        if tail == '':
            raise ValueError('should never occur')

        parent_dir = self._getpath(head)

        if parent_dir is None:
            print('{}: directory does not exist'.format(head))

        if tail not in parent_dir:
            # Create a new file and set its owner to this user.
            parent_dir.touch(tail)

        try:
            with open(src, 'rb') as f:
                data = src.read()
        except OSError:
            print('error: could not read file {}'.format(src))
            return

        parent_dir[tail].get_file().write(data)

    def do_ls(self, argline):
        """ Lists contents of the current working directory or provided
            directory. """
        args = shlex.split(argline)

        if len(args) == 0:
            cur = self.cur_dir
        else:
            cur = self._getpath(args[0])
            if cur is None:
                print('{}: no such directory'.format(args[0]))
                return

        print('  '.join(fn for fn in cur))

    def do_mkdir(self, argline):
        """ Makes the specified directories. """
        args = shlex.split(argline)

        if len(args) == 0:
            print('usage: mkdir <file> <file...>')
            return

        for arg in args:
            (head, tail) = os.path.split(arg.rstrip('/'))

            if tail == '':
                raise ValueError('should never occur')

            parent_dir = self._getpath(head)

            if parent_dir is None:
                print('{}: file not found'.format(arg))
                continue

            if tail in parent_dir:
                print('{}: already exists'.format(arg))
                continue

            parent_dir.mkdir(tail)

    def do_rm(self, argline):
        """ Deletes the provided file. """
        args = shlex.split(argline)

        if len(args) == 0:
            print('usage: rm <file> <file...>')
            return

        for arg in args:
            (head, tail) = os.path.split(arg.rstrip('/'))

            if tail == '':
                raise ValueError('should never occur')

            parent_dir = self._getpath(head)

            if parent_dir is None:
                print('{}: file not found'.format(arg))
                continue

            if tail not in parent_dir:
                print('{}: file not found'.format(arg))
                continue

            if not isinstance(parent_dir[tail], File):
                print('{}: not a file'.format(arg))
                continue

            parent_dir[tail].delete()
            del parent_dir[tail]

    def do_rmdir(self, argline):
        """ Deletes the provided directories. """
        args = shlex.split(argline)

        if len(args) == 0:
            print('usage: rmdir <dir> <dir...>')
            return

        for arg in args:
            (head, tail) = os.path.split(arg.rstrip('/'))

            if tail == '':
                raise ValueError('should never occur')

            parent_dir = self._getpath(head)

            if parent_dir is None:
                print('{}: file not found'.format(arg))
                continue

            if tail not in parent_dir:
                print('{}: file not found'.format(arg))
                continue

            del_dir = parent_dir[tail]
            if not isinstance(parent_dir[tail], Directory):
                print('{}: not a directory'.format(arg))
                continue

            if len(del_dir) != 0:
                print('{}: directory not empty'.format(arg))
                continue

            del_dir.delete()
            del parent_dir[tail]

    def do_exit(self, arg):
        print('goodbye')
        return True

    do_EOF = do_exit


if __name__ == '__main__':
    import sys

    if len(sys.argv) != 4:
        print('usage: {} <fs> <user_store> <username>'.format(sys.argv[0]))
        sys.exit(1)

    while True:
        repl = UserRepl(sys.argv[1], sys.argv[2], sys.argv[3])

        try:
            repl.cmdloop()
            break
        except:
            import traceback
            traceback.print_exc()

            print()
            print('**Caught exception. Restarting.**')
            print()

