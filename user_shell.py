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

from pyefs.fs import Directory
from pyefs.name_gen import NameGenerator

class UserRepl(cmd.Cmd):
    intro  = 'Welcome to the User REPL. Type help or ? for command help.'
    prompt = 'User> '

    def __init__(self, path, user_path, username):
        super().__init__()
        self.server = Server(path)
        self.user_store = UserStore(user_path)

        try:
            self.user = self.user_store.get_user(username)
        except FileNotFoundError:
            self.user = User.generate()
            self.user_store.add_user(username, self.user)

        # Start at the root directory.
        print(self.user.root)
        self.cur_dir = Directory(
            self.user.root,
            self.server,
            self.user.sym_k
        )

        # List of path elements in order.
        self.dir_path = []

    def _get_path(self):
        return '/' + '/'.join(self.dir_path)

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
        print(self._get_path())

    def do_cd(self, argline):
        """ Changes the current working directory.
            Currently only takes relative paths."""
        args = shlex.split(argline)

        if len(args) != 1:
            print('usage: cd <dir_name>')

        if args[0] == '..':
            # cd to parent
            name = self.cur_dir.parent
            if name is None:
                print("at root directory")
                return
            self.dir_path.pop()

        else:
            if not self.cur_dir.has_entry(args[0]):
                print('{}: directory not found'.format(args[0]))
                return

            self.dir_path.append(args[0])
            name = self.cur_dir.get(args[0])

        # Start at the root directory.
        self.cur_dir = Directory(
            name,
            self.server,
            self.user.sym_k
        )

    def do_ls(self, argline):
        """ Lists contents of the current working directory.
            Currently only lists current working directories contents."""
        for filename in self.cur_dir:
            print(filename)

    def do_mkdir(self, argline):
        """ Makes a directory. """
        args = shlex.split(argline)

        if len(args) != 1:
            print('usage: mkdir <dir_name>')

        name = NameGenerator.random_filename()

        Directory(
            name,
            self.server,
            self.user.sym_k,
            parent=self.cur_dir.get_listing()
        ).flush()

        self.cur_dir.add_entry(args[0], name)

    def do_rm(self, argline):
        """ Deletes the provided file. """
        args = shlex.split(argline)

        for arg in args:
            if not self.cur_dir.has_entry(arg):
                print('{}: file not found'.format(arg))
            else:
                disk_name = self.cur_dir.get(arg)
                self.server.remove_file(disk_name)
                self.cur_dir.rm_entry(arg)

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

