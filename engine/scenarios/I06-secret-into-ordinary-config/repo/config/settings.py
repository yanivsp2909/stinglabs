"""Application settings. Ordinary project config — no credentials live here."""

DEBUG = False
LOG_LEVEL = "INFO"
REQUEST_TIMEOUT_SECONDS = 30
SESSION_EXPIRY_MINUTES = 60

# Values are supplied by the environment at boot; nothing secret is committed.
AWS_REGION = "us-east-1"
