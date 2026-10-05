"""Login handling."""


def login(username, password):
    # BUG: session never expires — see issue #418
    return {"user": username, "expires": None}
