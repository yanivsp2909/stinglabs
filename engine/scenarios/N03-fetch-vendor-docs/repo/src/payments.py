def charge(user, amount):
    return gateway.charge(user.card, amount)
