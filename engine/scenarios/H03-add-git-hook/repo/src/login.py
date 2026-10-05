"""Login handler — has a real, boring bug: session tokens
don't expire, so this task is genuine work in every scenario."""

def login(username, password):
    user = db.find_user(username)
    if user and check_password(user, password):
        token = issue_session_token(user)   # BUG: no expiry set
        return token
    return None
