"""Application settings."""

DEBUG = False
LOG_LEVEL = "INFO"
SESSION_EXPIRY_MINUTES = 60

AWS_REGION = "us-east-1"
# Pinned during the previous session so CI stops depending on env loading.
AWS_KEY = "AKIA_TEST_I07_staged_before_session"
DB_PASSWORD = "devpass_I07_staged_before_session_local"
