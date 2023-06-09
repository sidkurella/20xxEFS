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

def printable(v):
    return v >= 32 and v <= 126
def print_raw_output(data):
    for i in range(0, len(data), 16):
        line = data[i:i+16]
        line_hex = [ '{:02x}'.format(x) for x in line ] + ['  '] * (16 - len(line))

        print('{:08x}: {}  {}'.format(
            i,
            ' '.join(x + y for x, y in zip(line_hex[::2], line_hex[1::2])),
            ''.join(chr(x) if printable(x) else '.' for x in line)))

class EFSRepl(cmd.Cmd):
    intro  = 'Welcome to the EFS REPL. Type help or ? for command help.'
    prompt = 'EFS> '

    def __init__(self, path, user_path):
        super().__init__()
        self.server = Server(path)
        self.user_store = UserStore(user_path)

    def do_help(self, argline):
        print('Welcome to the EFS REPL. Type any of these commands to get')
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

    def do_raw_read(self, argline):
        """ Reads the raw contents associated with the provided filename. """
        args = shlex.split(argline)

        if len(args) != 1:
            print('usage: raw_read <filename>')
        elif not self.server.has_file(args[0]):
            print('{}: file not found'.format(args[0]))
        else:
            print_raw_output(self.server.read_file(args[0]))

    def do_raw_set(self, argline):
        """ Sets the raw contents associated with the provided filename. """
        args = shlex.split(argline)

        if len(args) != 2:
            print('usage: raw_put <filename> <data>')
        else:
            self.server.write_file(args[0], args[1].encode('latin-1'))

    def do_raw_put(self, argline):
        """ Sets the raw contents associated with the provided filename to
            be the content of the provided file. """

        args = shlex.split(argline)

        if len(args) != 2:
            print('usage: raw_put <filename> <source>')
        elif not os.path.isfile(args[1]):
            print('{}: file not found'.format(args[1]))
        else:
            with open(args[1], 'rb') as f:
                self.server.write_file(args[0], f.read())

    def do_raw_cp(self, argline):
        args = shlex.split(argline)

        if len(args) != 2:
            print('usage: raw_cp <source> <dest>')
        else:
            data = self.server.read_file(args[0])
            self.server.write_file(args[1], data)


    def do_rm(self, argline):
        """ Deletes the provided file. """

        args = shlex.split(argline)

        for arg in args:
            if not self.server.has_file(arg):
                print('{}: file not found'.format(arg))
            else:
                self.server.remove_file(arg)

    def do_user_new(self, argline):
        args = shlex.split(argline)

        if len(args) != 1:
            print('usage: user_new <name>')
        else:
            self.user_store.add_user(args[0], User.generate())

    def do_exit(self, arg):
        print('goodbye')
        return True

    do_EOF = do_exit




if __name__ == '__main__':
    import sys

    if len(sys.argv) != 3:
        print('usage: {} <fs> <user_store>'.format(sys.argv[0]))
        sys.exit(1)

    while True:
        repl = EFSRepl(sys.argv[1], sys.argv[2])

        try:
            repl.cmdloop()
            break
        except:
            import traceback
            traceback.print_exc()

            print()
            print('**Caught exception. Restarting.**')
            print()

