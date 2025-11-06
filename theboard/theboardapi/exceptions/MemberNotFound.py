from theboardapi.models import TheBoardMember


class MemberNotFound(Exception):

    def __init__(self, screen_name):
        self.message = f"Member {screen_name} not found"
        super().__init__(self.message)