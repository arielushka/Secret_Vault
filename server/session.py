class Session:
    # A session holds the authenticated user for one connected client.
    def __init__(self):
        self.user_id = None

    def login(self, user_id):
        # Keep only the account ID needed to authorize later requests.
        self.user_id = user_id

    def logout(self):
        # Clearing the ID makes protected actions require login again.
        self.user_id = None

    def is_authenticated(self):
        # A session is authenticated while it has a user ID.
        return self.user_id is not None
