
class InvalidPassword(Exception):

    def __init__(self):
        self.message = "Password not matched"
        super().__init__(self.message)