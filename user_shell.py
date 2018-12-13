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

from pyefs.fs import Directory, File, FileMetadata
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

            self.user = User.generate(username)
            self.user_store.add_user(username, self.user)

        # Create auth for user
        self.auth = self.user.auth()

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
            result = self._getpath(args[0])
            if isinstance(result, FileMetadata):
                print('{}: not a directory'.format(args[0]))
                return
            new_dir = result

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

        # The directory entry gives us the file permission record, which will
        # allow us to read the file.
        fpr = parent_dir[tail]
        try:
            with open(dst, 'wb') as f:
                f.write(fpr.get_file().read())
        except OSError:
            print('error: could not write to {}'.format(dst))

    def do_cat(self, argline):
        args = shlex.split(argline)

        if len(args) == 0:
            print('usage: cat <files>')
            return

        for arg in args:
            f = self._getpath(arg)

            if not isinstance(f, FileMetadata):
                print('{}: not a file'.format(arg))
                return

            print(f.file().read().decode('utf-8'), end='')

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
            parent_dir[tail].grant(self.auth, writable=True)

        try:
            with open(src, 'rb') as f:
                data = f.read()
        except OSError:
            print('error: could not read file {}'.format(src))
            return

        parent_dir[tail].file().write(data)


    def do_grant_rw(self, argline):
        """ Grants read-write permissions on the specified file, for the
            specified user. """
        self._grant(True, argline)

    def do_grant_ro(self, argline):
        """ Grants read-only permissions on the specified file, for the
            specified user. """
        self._grant(False, argline)

    def _grant(self, writable, argline):
        """ Grants specified permission level on the specified file, for the
            specified user. """
        args = shlex.split(argline)

        if len(args) != 2:
            print('usage: grant_* <file> <user>')
            return

        f = self._getpath(args[0])
        if not isinstance(f, FileMetadata):
            print('{}: not a file'.format(f))
            return

        user = self.user_store.get_user_public(args[1]).auth()
        f.grant(user, writable)

        token = user.hybrid_encrypt((self.auth.public_key(), f.raw_name))

        print(base64.b64encode(token).decode('ascii'))

    def do_receive(self, argline):
        """ Receives a shared file into the specified location. """
        args = shlex.split(argline)

        if len(args) != 2:
            print('usage: receive <file> <token>')
            return

        dst = args[0]
        token = base64.b64decode(args[1])
        pk, fp = self.auth.hybrid_decrypt(token)

        (head, tail) = os.path.split(dst.rstrip('/'))

        if tail == '':
            raise ValueError('should never occur')

        parent_dir = self._getpath(head)

        if parent_dir is None:
            print('{}: file not found'.format(arg))
            return

        if tail in parent_dir:
            print('{}: already exists'.format(arg))
            return

        parent_dir.receive(dst, fp, pk)

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

            if not isinstance(parent_dir[tail], FileMetadata):
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

