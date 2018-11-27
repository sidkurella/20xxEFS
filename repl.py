#!/bin/env python3

import cmd
from itertools import zip_longest

from server import Server

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

    def __init__(self, path):
        super().__init__()
        self.server = Server(path)

    def do_help(self, args):
        print('TODO:', args)

    def do_raw_read(self, arg):
        fn = arg.encode('utf-8')

        if self.server.has_file(fn):
            print_raw_output(self.server.read_file(fn))
        else:
            print('file {!r} does not exist'.format(fn))
    do_rr = do_raw_read

    def do_raw_write(self, arg):
        [fn, data] = [x.encode('utf-8') for x in arg.split(' ', 2)]
        self.server.write_file(fn, data)
    do_rw = do_raw_write

    def do_raw_copy(self, arg):
        [fn_str, src] = arg.split(' ', 2)
        fn = fn_str.encode('utf-8')

        try:
            with open(src, 'rb') as fp:
                self.server.write_file(fn, fp.read())
        except FileNotFoundError:
            print('file {} does not exist', src)

    def do_exit(self, arg):
        self.server.flush()

        print('goodbye')
        return True
    do_quit = do_exit
    do_q    = do_exit
    do_EOF  = do_exit




if __name__ == '__main__':
    import sys

    if len(sys.argv) != 2:
        print('usage: {} file'.format(sys.argv[0]))
        sys.exit(1)

    EFSRepl(sys.argv[1]).cmdloop()

