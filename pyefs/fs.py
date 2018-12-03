class FilesystemObject:
    def __init__(self, disk_name):
        self.disk_name = disk_name

    def get_listing(self):
        return self.disk_name

class Directory(FilesystemObject):
    def __init__(self, disk_name):
        super().__init__(disk_name)
        self.entries = dict()

    def add_entry(filename, listing):
        pass

    def rm_entry(filename):
        pass

class File(FilesystemObject):
    def __init__(self, disk_name):
        super().__init__(disk_name)
        self.perm_blocks = dict()

    def add_perm(username, pk, acc_type):
        pass

class FilePermBlock:
    pass
