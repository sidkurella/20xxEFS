class EFSManager:
    def __init__(self, server):
        '''Initializes an EFSManager.

        params:
            server: Instance of file server implementation
            user_store: This user's secrets information.'''
        self.server = server
