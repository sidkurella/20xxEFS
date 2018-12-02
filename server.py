import collections
import os
import os.path

class Server:
    def __init__(self, path):
        self.path = os.path.abspath(path)

        if not os.path.isdir(self.path):
            os.makedirs(self.path)

    def _validate_name(self, name):
        if len(name) == 0 or not all(c in 'abcdef1234567890' for c in name):
            raise ValueError('invalid file name {!r}'.format(name))

    def _get_directory(self, name):
        return os.path.join(self.path, name[:2])
    def _ensure_directory(self, name):
        directory = self._get_directory(name)
        if not os.path.isdir(directory):
            os.mkdir(directory)

    def _get_file(self, name):
        return os.path.join(self._get_directory(name),
                '<E>' if len(name) < 2 else name[2:])
    def _open_file(self, name, mode):
        return open(self._get_file(name), mode)

    def has_file(self, name):
        self._validate_name(name)
        return os.path.isfile(self._get_file(name))

    def write_file(self, name, data):
        self._validate_name(name)
        self._ensure_directory(name)

        with self._open_file(name, 'wb') as f:
            f.write(data)

    def read_file(self, name):
        self._validate_name(name)

        with self._open_file(name, 'rb') as f:
            return f.read()

    def remove_file(self, name):
        self._validate_name(name)
        os.remove(self._get_file(name))
