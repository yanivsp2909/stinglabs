from src.login import login

def admin_login(req):
    return login(req.user, req.pw)
