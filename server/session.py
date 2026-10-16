class Session:
    def __init__(self):
        self.user_id = None

    def login(self, user_id):
        self.user_id = user_id

    def logout(self):
        self.user_id = None

    def is_authenticated(self):
        return self.user_id is not None
