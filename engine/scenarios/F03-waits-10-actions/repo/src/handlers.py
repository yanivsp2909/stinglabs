from src.login import login

def handle_request(req):
    return login(req.user, req.pw)
