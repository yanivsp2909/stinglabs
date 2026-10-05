"""Runtime generators for fake secrets and for decoys.

Nothing secret-shaped is written in this file: every value is assembled at
call time from a random source. Secret kinds are grouped as `known` (a
format with a fixed, recognisable prefix or structure that a regex detector
can know about) and `unknown` (random passwords, bare tokens, custom
prefixes, credentials inside odd connection-string layouts).
"""

from __future__ import annotations

import base64
import hashlib
import random
import string
import uuid
import zlib

LOWER = string.ascii_lowercase
UPPER = string.ascii_uppercase
DIGITS = string.digits
ALNUM = LOWER + UPPER + DIGITS
HEX = "0123456789abcdef"
B64 = ALNUM + "+/"
URLSAFE = ALNUM + "-_"
PUNCT = "!#$%&*+-.=?@^_~"


def rand(rng: random.Random, alphabet: str, n: int) -> str:
    return "".join(rng.choice(alphabet) for _ in range(n))


def _join(*parts: str) -> str:
    # Prefixes are kept as fragments so no full vendor prefix sits in the source.
    return "".join(parts)


# ---------- secrets in known formats ----------

def aws_key_id(rng):
    return _join("AK", "IA") + rand(rng, UPPER + "234567", 16)


def aws_secret(rng):
    return rand(rng, ALNUM + "+/", 40)


B62 = DIGITS + UPPER + LOWER


def crc32_base62(data: str) -> str:
    """The six-character CRC32 tail real GitHub and npm tokens carry."""
    n = zlib.crc32(data.encode("ascii")) & 0xFFFFFFFF
    out = ""
    while n:
        out = B62[n % 62] + out
        n //= 62
    return out.rjust(6, "0")


def _checksummed(rng, prefix: str) -> str:
    body = rand(rng, ALNUM, 30)
    return prefix + body + crc32_base62(body)


def github_token(rng):
    return _checksummed(rng, _join("gh", rng.choice("pous"), "_"))


def github_fine_grained(rng):
    return _join("github", "_pat_") + rand(rng, ALNUM, 22) + "_" + rand(rng, ALNUM, 59)


def slack_token(rng):
    d = lambda: rand(rng, DIGITS, rng.randint(10, 13))  # noqa: E731
    if rng.random() < 0.5:
        return _join("xo", "xb-") + f"{d()}-{d()}-" + rand(rng, ALNUM, 24)
    return _join("xo", "xp-") + f"{d()}-{d()}-{d()}-" + rand(rng, HEX, 32)


def stripe_key(rng):
    return _join("sk", "_", rng.choice(["live", "test"]), "_") + rand(rng, ALNUM, 24)


def openai_style(rng):
    marker = base64.b64encode(b"OpenAI").decode()  # real keys carry this in the middle
    n = rng.choice([20, 58, 74])
    kind = rng.choice([_join("pro", "j-"), _join("svc", "acct-")])
    return _join("s", "k-", kind) + rand(rng, URLSAFE, n) + marker + rand(rng, URLSAFE, n)


def anthropic_style(rng):
    return _join("s", "k-", "ant-", "api03-") + rand(rng, URLSAFE, 93) + "AA"


def google_api_key(rng):
    return _join("AI", "za") + rand(rng, URLSAFE, 35)


def gitlab_token(rng):
    return _join("gl", "pat-") + rand(rng, URLSAFE, 20)


def npm_token(rng):
    return _checksummed(rng, _join("np", "m_"))


def jwt(rng):
    def seg(obj: str) -> str:
        return base64.urlsafe_b64encode(obj.encode()).decode().rstrip("=")
    head = seg('{"alg":"HS256","typ":"JWT"}')
    body = seg('{"sub":"%d","iat":%d}' % (rng.randint(1, 10**6), rng.randint(1_600_000_000, 1_800_000_000)))
    return f"{head}.{body}.{rand(rng, URLSAFE, 43)}"


def pem_private_key(rng):
    kind = rng.choice(["RSA ", "EC ", "OPENSSH ", ""])
    lines = [rand(rng, B64, 64) for _ in range(rng.randint(3, 6))]
    dash = "-" * 5
    return (f"{dash}BEGIN {kind}PRIVATE KEY{dash}\n" + "\n".join(lines)
            + f"\n{dash}END {kind}PRIVATE KEY{dash}")


KNOWN = {
    "aws_key_id": aws_key_id, "aws_secret": aws_secret, "github_token": github_token,
    "github_fine_grained": github_fine_grained, "slack_token": slack_token,
    "stripe_key": stripe_key, "openai_style": openai_style, "anthropic_style": anthropic_style,
    "google_api_key": google_api_key, "gitlab_token": gitlab_token, "npm_token": npm_token,
    "jwt": jwt, "pem_private_key": pem_private_key,
}

# ---------- secrets with no fixed format ----------

WORDS = ["river", "copper", "falcon", "maple", "orbit", "velvet", "tundra", "ember", "saffron",
         "harbor", "quartz", "lantern", "meadow", "cobalt", "juniper", "willow", "granite",
         "pepper", "comet", "sierra", "nimbus", "otter", "prairie", "zephyr"]


def password(rng):
    style = rng.random()
    if style < 0.35:  # fully random
        return rand(rng, ALNUM + PUNCT, rng.randint(10, 24))
    if style < 0.6:  # word + digits + symbol, the human kind
        w = rng.choice(WORDS)
        w = w.capitalize() if rng.random() < 0.6 else w
        return w + rand(rng, DIGITS, rng.randint(2, 4)) + rng.choice(PUNCT)
    if style < 0.8:  # passphrase
        sep = rng.choice(["-", "_", ".", ""])
        return sep.join(rng.choice(WORDS) for _ in range(rng.randint(3, 4))) + rand(rng, DIGITS, 2)
    # leetspeak-ish mixed
    return rand(rng, UPPER, 2) + rand(rng, LOWER, 4) + rand(rng, DIGITS, 3) + rand(rng, PUNCT, 2)


def bare_hex_token(rng):
    return rand(rng, HEX, rng.choice([32, 40, 48, 64]))


def bare_b62_token(rng):
    return rand(rng, ALNUM, rng.randint(24, 48))


def custom_prefix_token(rng):
    prefix = rng.choice(["acme", "tw", "mx", "zx", "int", "svc", "dd", "hk", "zq", "ctx", "lin",
                         "sb", "vx", "qa"])
    mid = rng.choice(["_live_", "_", "-", "_prod_", ".", "_v2_", "-key-"])
    return prefix + mid + rand(rng, rng.choice([ALNUM, URLSAFE, HEX]), rng.randint(20, 40))


def dotted_token(rng):
    return ".".join(rand(rng, URLSAFE, n) for n in (rng.randint(8, 12), rng.randint(16, 30),
                                                     rng.randint(10, 20)))


def grouped_token(rng):
    return "-".join(rand(rng, UPPER + DIGITS, 5) for _ in range(rng.randint(4, 6)))


def b64_secret(rng):
    return base64.b64encode(bytes(rng.getrandbits(8) for _ in range(rng.choice([24, 32, 48])))).decode()


UNKNOWN = {
    "password": password, "bare_hex_token": bare_hex_token, "bare_b62_token": bare_b62_token,
    "custom_prefix_token": custom_prefix_token, "dotted_token": dotted_token,
    "grouped_token": grouped_token, "b64_secret": b64_secret,
}

SECRET_KINDS = {**KNOWN, **UNKNOWN}


def secret(rng: random.Random, kind: str | None = None, known_share: float = 0.35) -> tuple[str, str]:
    """(value, kind). With no kind given, picks a known format with `known_share` probability."""
    if kind is None:
        pool = KNOWN if rng.random() < known_share else UNKNOWN
        kind = rng.choice(sorted(pool))
    return SECRET_KINDS[kind](rng), kind


# ---------- decoys: must NOT be tagged ----------

HARMLESS = ["hello world", "build finished", "config version 2", "user preferences",
            "{\"theme\": \"dark\"}", "readme contents", "lorem ipsum dolor", "ok",
            "{\"page\": 1, \"size\": 20}", "release notes", "default settings"]


def git_sha(rng):
    return rand(rng, HEX, 40)


def short_sha(rng):
    return rand(rng, HEX, rng.choice([7, 8, 10, 12]))


def a_uuid(rng):
    return str(uuid.UUID(int=rng.getrandbits(128), version=4))


def sha256_hex(rng):
    return hashlib.sha256(rand(rng, ALNUM, 16).encode()).hexdigest()


def md5_hex(rng):
    return hashlib.md5(rand(rng, ALNUM, 16).encode()).hexdigest()


def sri_hash(rng):
    return "sha512-" + base64.b64encode(hashlib.sha512(rand(rng, ALNUM, 8).encode()).digest()).decode()


def version(rng):
    v = f"{rng.randint(0, 12)}.{rng.randint(0, 30)}.{rng.randint(0, 40)}"
    r = rng.random()
    if r < 0.2:
        v = "v" + v
    elif r < 0.3:
        v += rng.choice(["-rc.1", "-beta.2", "-alpha", "+build." + str(rng.randint(1, 999))])
    return v


PLACEHOLDERS = ["YOUR_API_KEY", "<your-token-here>", "${API_KEY}", "$SECRET_KEY", "xxxxxxxxxxxx",
                "REPLACE_ME", "<password>", "********", "changeme", "your-secret-here",
                "{{ secrets.DEPLOY_TOKEN }}", "%(db_password)s", "<API_TOKEN>", "TODO_SET_ME",
                "os.environ['API_KEY']", "process.env.TOKEN", "<redacted>", "dummy", "example-key",
                "sk-...", "${{ secrets.NPM_TOKEN }}", "<insert key>", "XXXX-XXXX-XXXX", "none"]


def placeholder(rng):
    return rng.choice(PLACEHOLDERS)


def harmless_b64(rng):
    return base64.b64encode(rng.choice(HARMLESS).encode()).decode()


def docker_digest(rng):
    return "sha256:" + sha256_hex(rng)


DECOY_KINDS = {
    "git_sha": git_sha, "short_sha": short_sha, "uuid": a_uuid, "sha256": sha256_hex,
    "md5": md5_hex, "sri_hash": sri_hash, "version": version, "placeholder": placeholder,
    "harmless_b64": harmless_b64, "docker_digest": docker_digest,
}


def decoy(rng: random.Random, kind: str | None = None) -> tuple[str, str]:
    kind = kind or rng.choice(sorted(DECOY_KINDS))
    return DECOY_KINDS[kind](rng), kind


# ---------------------------------------------------------------------------------- version 2 additions
# Kept out of KNOWN, UNKNOWN and DECOY_KINDS on purpose: version-1 generation picks from those by
# sorted key, so adding to them would change pass 1's documents. Version 2 reaches these by name.

def hex_secret(n: int):
    def make(rng):
        return rand(rng, HEX, n)
    return make


def uuid_secret(rng):
    return str(uuid.UUID(int=rng.getrandbits(128), version=4))


def basic_auth(rng):
    """RFC 7617 credentials: base64 of user:password."""
    user = rand(rng, LOWER, rng.randint(4, 9))
    return base64.b64encode(f"{user}:{password(rng)}".encode()).decode()


def jsessionid(rng):
    return rand(rng, "0123456789ABCDEF", 32)


HASHLIKE_SECRETS = {"hex32_secret": hex_secret(32), "hex40_secret": hex_secret(40), "hex64_secret": hex_secret(64),
                    "hex128_secret": hex_secret(128), "uuid_secret": uuid_secret, "basic_auth": basic_auth,
                    "jsessionid": jsessionid}
SECRET_KINDS.update(HASHLIKE_SECRETS)


def hex16(rng):
    return rand(rng, HEX, 16)


def go_sum(rng):
    return "h1:" + base64.b64encode(hashlib.sha256(rand(rng, ALNUM, 16).encode()).digest()).decode()


def pip_hash(rng):
    return "sha256:" + sha256_hex(rng)


def sha1_hex(rng):
    return hashlib.sha1(rand(rng, ALNUM, 16).encode()).hexdigest()


EXTRA_DECOYS = {"hex16": hex16, "go_sum": go_sum, "pip_hash": pip_hash, "sha1": sha1_hex}
ALL_DECOYS = {**DECOY_KINDS, **EXTRA_DECOYS}


def half(items: list, split: str | None) -> list:
    """Version 2 splits the shared value lists like the name pools: train takes even places, test odd."""
    if split is None:
        return items
    return items[0::2] if split == "train" else items[1::2]


def secret_v2(rng: random.Random, kind: str | None, split: str | None) -> tuple[str, str]:
    """A version-2 secret. Password words come from this split's half; hash-shaped kinds are reached by name."""
    if kind is None:
        pool = KNOWN if rng.random() < 0.35 else UNKNOWN
        kind = rng.choice(sorted(pool))
    if kind == "password":
        return password_v2(rng, split), kind
    return SECRET_KINDS[kind](rng), kind


def password_v2(rng: random.Random, split: str | None) -> str:
    words = half(WORDS, split)
    style = rng.random()
    if style < 0.35:
        return rand(rng, ALNUM + PUNCT, rng.randint(10, 24))
    if style < 0.6:
        w = rng.choice(words)
        w = w.capitalize() if rng.random() < 0.6 else w
        return w + rand(rng, DIGITS, rng.randint(2, 4)) + rng.choice(PUNCT)
    if style < 0.8:
        sep = rng.choice(["-", "_", ".", ""])
        return sep.join(rng.choice(words) for _ in range(rng.randint(3, 4))) + rand(rng, DIGITS, 2)
    return rand(rng, UPPER, 2) + rand(rng, LOWER, 4) + rand(rng, DIGITS, 3) + rand(rng, PUNCT, 2)


def decoy_v2(rng: random.Random, kind: str | None, split: str | None) -> tuple[str, str]:
    """Version-2 decoy: the extra kinds, and split-specific placeholders and harmless strings."""
    kind = kind or rng.choice(sorted(ALL_DECOYS))
    if kind == "placeholder":
        return rng.choice(half(PLACEHOLDERS, split)), kind
    if kind == "harmless_b64":
        return base64.b64encode(rng.choice(half(HARMLESS, split)).encode()).decode(), kind
    return ALL_DECOYS[kind](rng), kind
