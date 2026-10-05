"""Known-format secret detection — Feeder B of the secret-detection umbrella.

Recognise fixed-shape credentials by the FORMAT their vendor publishes: a
namespaced prefix, a fixed character set and length, and — where the vendor
built one in — a checksum or a marker. Nothing here reads a file, asks a
network or weighs entropy. It answers one question, `find_known_secret(text)`,
and the engine asks it in exactly one place: `carries_secret()`, as the third
disjunct beside "ships the environment" and "matches a fingerprint the session
already read". `find_known_secrets(text)` answers the one behind it — WHICH
values, all of them, in order — for the reason and the evidence. Provenance is
untouched and still covers shapeless secrets — names, passwords, anything
whose only signal is where it came from.

────────────────────────────────────────────────────────────────────────────────
WHY FORMAT AND NOT ENTROPY
────────────────────────────────────────────────────────────────────────────────

A vendor prefix is a signal the attacker cannot choose (working rule #5):
nothing in an ordinary codebase starts with `AKIA` or `ghp_` except the real
thing. Randomness is a signal the *world* produces constantly — git hashes,
UUIDs, base64 ids, `python3.12` — which is why the entropy guard built in PR
#21 was removed in #22 (docs/83) and why this module contains no entropy
measure of any kind. Every rule here has a structural discriminator beyond the
prefix — a checksum, a marker, a decodable payload, or an exact charset+length
— and a test asserts the word "entropy" never appears in this file's code.

────────────────────────────────────────────────────────────────────────────────
WHERE THE TABLE COMES FROM — AND THE NOTICE THAT TRAVELS WITH IT
────────────────────────────────────────────────────────────────────────────────

The patterns are transcribed from Betterleaks' generated ruleset (MIT,
© Zachary Rice — the gitleaks author's successor set, 462 rules) and cross-
checked against gitleaks (MIT, same author) and Nosey Parker (Apache-2.0,
Praetorian), whose per-rule vendor references and negative examples were used
to confirm each shape. `NOTICE` at the repository root carries their licence
text. Nothing was taken from trufflehog (AGPL-3.0) or secrets-patterns-db
(CC-BY-SA-4.0). Each `Format.source` names the rule it came from so a later
widening toward Betterleaks' 247 prefix-anchored rules can be diffed against
its origin. docs/85 records the research; PROGRESS.md the decision.

Their entropy gates (`entropy = 3` in gitleaks, `filter = "entropy(...) <= 3"`
in Betterleaks, on 107 of gitleaks' 121 prefix rules) are NOT transcribed —
replaced by the structure column below. Their live `validate` blocks (HTTP
calls to the vendor) are not transcribed either: this runs on the hot path.

────────────────────────────────────────────────────────────────────────────────
LOCKED DECISIONS (the owner's, 2026-09-07)
────────────────────────────────────────────────────────────────────────────────

  * Google `AIza…` keys are NOT in the table. Firebase documents them as safe
    to embed in client code; flagging them is a false positive by design.
  * Vendor TEST keys are never flagged: Stripe `sk_test_`/`rk_test_` do not
    match — only `_live_` does. Publishable `pk_` keys are public and absent.
  * JWTs are NOT in the table: a Supabase anon key is a public JWT.
  * A hit raises the EXISTING `secret_exact` verdict through the existing
    ladder. There is no new verdict, no new rule id.

────────────────────────────────────────────────────────────────────────────────
HOW IT STAYS UNDER THE BUDGET
────────────────────────────────────────────────────────────────────────────────

Two stages, neither of which is "200 regexes over the whole text":

  1. PREFILTER — `str.find` of each literal prefix and marker over the text
     (C speed, ~100 substrings). Almost every command has none of them and
     returns here. The cost is linear in that count on a text that carries no
     trigger — measured, not assumed: `tools/bench_known_formats.py` reports the
     32 KB no-trigger scan, the worst case for the prefilter.
  2. On a prefilter hit, every OCCURRENCE of each present prefix is tried —
     `str.find` again, so an adversarial text of three thousand `AKIA`s costs
     three thousand cheap anchored matches, not a backtracking scan — and only
     the handful of formats behind that prefix run their exact shape and, if
     they have one, their checksum. Text-level formats (a PEM block, a webhook
     URL) search the text once from their marker.

⚠ A PREFIX MAY SIT ANYWHERE, AND THE END IS WHAT DELIMITS. `x-AKIA…`,
`req_ghp_…` and `id=AKIA…` are all a working key to the receiver, who strips
the glue, so the shape is tried wherever its prefix occurs. What still ends a
candidate is the END boundary: a key followed by more alphanumerics is a
longer string that merely begins like one (`ghp_<36>abc` is not a token).

⚠ AND SHELL GLUE IS SEEN THROUGH. `AKIA""QZXW…`, `"AKIA"'QZXW…'` and
`AKIA\\QZXW…` are one argument to the shell and two runs to the text — the
first bypass the security review found. When the first pass sees nothing and
the text carries a quote or a backslash, a second pass runs over the text
with those characters removed, and a hit's offsets are mapped back through
the removed positions so the evidence still points into the raw command.

`MAX_SCAN` is pinned equal to the engine's: a secret beyond 128 KB into one
action is not seen, the same honest limit the fingerprint scan states.

⚠ YES OR NO, WHICH VALUE, AND AT WHAT COST (security and python review,
fix/known-formats-all-matches). Three questions, three costs:

  `holds_known_secret`  yes or no, on EVERY action (`carries_secret`). The
                        one-hit matcher, unchanged in answer and in cost.
  `find_known_secret`   the LEFTMOST value, for the reason and the offset,
                        asked only once an action is found to carry one. Each
                        prefix is searched only up to the leftmost start found
                        so far; its ceiling is the one-hit matcher's walk over
                        the same text with its value removed.
  `masked_spans`        what the evidence window must hide, searched only as
                        far as that window can reach.

`find_known_secrets` reads every value and nothing on the hot path asks it.
tools/bench_known_formats.py times the first two on five texts.

────────────────────────────────────────────────────────────────────────────────
WHAT A HIT CARRIES, AND WHAT IT MUST NEVER CARRY
────────────────────────────────────────────────────────────────────────────────

A `Hit` is a format id, the format's display NAME ("an AWS access key ID") and
the [start, end) offsets of the match in the RAW text. It never carries the
matched value: the reason a developer reads is composed from the name, and
the engine's evidence for a format hit is the usual ±60-character window with
EVERY value in it replaced by `<name, N chars>` — so the span that sits in the
local log, and ships at `full`, names what was there without repeating it.
Every tier below `full` ships only its `@<offset>` (core/evidence.py,
core/wire.py; REASONED since #74). Pinned by
tests/test_feeder_b_redaction_is_pinned.py and
tests/test_known_formats_all_matches.py.
"""
from __future__ import annotations

import base64
import binascii
import json
import re
import string
import zlib
from dataclasses import dataclass

MAX_SCAN = 128 * 1024
"""Bytes of text inspected. Pinned equal to `engine._MAX_SCAN` by a test —
128 KB, widened from 32 KB after measuring that the cost is tail-only (the
typical diff is far smaller) and 128 KB is the largest flat window under the
12 ms A6a budget; see the reasoning at `engine._MAX_SCAN`."""

_SHELL_GLUE = re.compile(r"[\"'\\]")
"""What the shell removes between two runs of one argument: quotes and the
escaping backslash. The second pass sees the text without them."""

_BASE62 = string.digits + string.ascii_uppercase + string.ascii_lowercase
"""GitHub's base62 alphabet, digits first. Verified against a real token: the
CRC32 of the 30 random characters (prefix excluded), base62-encoded with this
alphabet and left-padded with `0` to six characters, equals the token's tail.
github.blog, "Behind GitHub's new authentication token formats", 2021-04-05;
npm adopted the same tail ("Announcing npm's new access token format")."""


def crc32_base62(data: str) -> str:
    """CRC32 of `data`, as six base62 characters, leading zeros kept."""
    n = zlib.crc32(data.encode("ascii")) & 0xFFFFFFFF
    out = ""
    while n:
        out = _BASE62[n % 62] + out
        n //= 62
    return out.rjust(6, "0")


def _tail_checksum_holds(token: str, prefix_len: int) -> bool:
    """`<prefix><random><6-char CRC32 tail>` — the GitHub/npm scheme."""
    body = token[prefix_len:]
    return len(body) > 6 and crc32_base62(body[:-6]) == body[-6:]


@dataclass(frozen=True)
class Format:
    """One documented credential shape. DATA: add a row, not a branch."""

    id: str
    name: str
    """What the reason says — "an AWS access key ID". Never the value."""
    prefixes: tuple[str, ...]
    """Literal starts a token must have. Empty for text-level formats."""
    shape: str
    """The exact regex. Anchored at the token start by the matcher; for a
    text-level format, searched in the text from its marker."""
    check: str | None = None
    """A validator name from `_CHECKS`, for formats that carry a checksum."""
    markers: tuple[str, ...] = ()
    """Text-level formats: substrings that prefilter the whole text."""
    source: str = ""
    """Where the shape was borrowed from, for the NOTICE and for diffs."""


@dataclass(frozen=True)
class Hit:
    format_id: str
    name: str
    start: int
    end: int


_ENROL_PREFIX = "sting-enrol-v1."


def _enrolment_payload_holds(value: str) -> bool:
    """`sting-enrol-v1.<base64url>`: the body decodes (padding restored, as
    installer/enrol.py decodes it) to an object carrying a `url` and a
    `secret`. The payload is the structural discriminator, as a checksum is for
    a GitHub token: a prefix over anything else is not one."""
    body = value[len(_ENROL_PREFIX):].rstrip("=")
    try:
        fields = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return False
    return (isinstance(fields, dict) and isinstance(fields.get("url"), str)
            and isinstance(fields.get("secret"), str)
            and bool(fields["url"]) and bool(fields["secret"]))


_CHECKS = {
    # 4 = len("ghp_") = len("npm_"): the prefix is excluded from the CRC.
    "crc32-base62-tail": lambda token: _tail_checksum_holds(token, 4),
    "sting-enrolment-payload": _enrolment_payload_holds,
}

_B64URL = r"[A-Za-z0-9_-]"

FORMATS: tuple[Format, ...] = (
    Format("aws-access-key-id", "an AWS access key ID",
           ("AKIA", "ASIA", "ABIA", "ACCA", "A3T"),
           r"(?:AKIA|ASIA|ABIA|ACCA|A3T[A-Z0-9])[A-Z2-7]{16}",
           source="betterleaks:aws-access-token; AWS IAM access-key reference"),
    Format("github-token", "a GitHub token",
           ("ghp_", "gho_", "ghu_", "ghs_"),
           r"gh[pous]_[A-Za-z0-9]{36}", check="crc32-base62-tail",
           source="betterleaks:github-pat/github-oauth/github-app-token; "
                  "github.blog 2021-04-05 (CRC32 base62 tail)"),
    Format("github-refresh-token", "a GitHub refresh token",
           ("ghr_",), r"ghr_[A-Za-z0-9]{76}",
           source="noseyparker:np.github.4"),
    Format("github-fine-grained-pat", "a GitHub fine-grained personal access token",
           ("github_pat_",), r"github_pat_[A-Za-z0-9_]{82}",
           source="betterleaks:github-fine-grained-pat"),
    Format("gitlab-personal-access-token", "a GitLab personal access token",
           ("glpat-",),
           rf"glpat-(?:{_B64URL}{{27,300}}\.[0-9a-z]{{2}}[0-9a-z]{{7}}|{_B64URL}{{20}})",
           source="betterleaks:gitlab-pat, gitlab-pat-routable"),
    Format("gitlab-service-token",
           "a GitLab deploy, runner, feed, SCIM, agent, OAuth-app, trigger or job token",
           ("gldt-", "glrt-", "glft-", "glsoat-", "glagent-", "gloas-", "glptt-", "glcbt-"),
           rf"(?:gl(?:dt|rt|ft|soat)-{_B64URL}{{20}}|glagent-{_B64URL}{{50}}"
           rf"|gloas-{_B64URL}{{64}}|glptt-[0-9a-f]{{40}}"
           rf"|glcbt-[A-Za-z0-9]{{1,5}}_{_B64URL}{{20}})",
           source="betterleaks:gitlab-* ; docs.gitlab.com/security/tokens"),
    Format("openai-api-key", "an OpenAI API key",
           ("sk-proj-", "sk-svcacct-", "sk-admin-", "sk-"),
           rf"(?:sk-(?:proj|svcacct|admin)-(?:{_B64URL}{{74}}|{_B64URL}{{58}}|{_B64URL}{{20}})"
           rf"T3BlbkFJ(?:{_B64URL}{{74}}|{_B64URL}{{58}}|{_B64URL}{{20}})"
           r"|sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20})",
           source="betterleaks:openai-api-key (T3BlbkFJ = base64 'OpenAI')"),
    Format("anthropic-api-key", "an Anthropic API key",
           ("sk-ant-api",), rf"sk-ant-api[0-9]{{2}}-{_B64URL}{{93}}AA",
           source="betterleaks:anthropic-api-key; noseyparker:np.anthropic.1"),
    Format("stripe-live-key", "a Stripe live secret or restricted key",
           ("sk_live_", "rk_live_"), r"[sr]k_live_[A-Za-z0-9]{24,99}",
           source="betterleaks:stripe-access-token, live keys only by decision"),
    Format("slack-token", "a Slack bot, user or app token",
           ("xoxb-", "xoxp-", "xapp-"),
           r"(?:xoxb-[0-9]{10,13}-(?:[0-9]{10,13}-)?[A-Za-z0-9]{24}"
           r"|xoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[a-f0-9]{32}"
           r"|xapp-[0-9]-[A-Z0-9]{8,14}-[0-9]{10,14}-[a-z0-9]{32,64})",
           source="betterleaks:slack-*; noseyparker:np.slack.*; docs.slack.dev"),
    Format("slack-webhook-url", "a Slack incoming-webhook URL", (),
           r"https://hooks\.slack\.com/services/T[A-Z0-9]{8,12}/B[A-Z0-9]{8,12}/[A-Za-z0-9]{24}",
           markers=("hooks.slack.com/services/",),
           source="betterleaks:slack-webhook-url; noseyparker:np.slack.6"),
    Format("npm-access-token", "an npm access token",
           ("npm_",), r"npm_[A-Za-z0-9]{36}", check="crc32-base62-tail",
           source="betterleaks:npm-access-token; github.blog npm token format"),
    Format("pypi-upload-token", "a PyPI upload token",
           ("pypi-AgEIcHlwaS5vcmc",), rf"pypi-AgEIcHlwaS5vcmc{_B64URL}{{50,}}",
           source="betterleaks:pypi-upload-token (marker = base64 'pypi.org')"),
    Format("huggingface-token", "a Hugging Face user access token",
           ("hf_",), r"hf_[A-Za-z]{34}",
           source="betterleaks:huggingface-access-token"),
    Format("sendgrid-api-key", "a SendGrid API key",
           ("SG.",), rf"SG\.{_B64URL}{{22}}\.{_B64URL}{{43}}",
           source="noseyparker:np.sendgrid.1; betterleaks:sendgrid-api-token"),
    Format("twilio-api-key", "a Twilio API key",
           ("SK",), r"SK[0-9a-fA-F]{32}",
           source="betterleaks:twilio-api-key"),
    Format("digitalocean-token", "a DigitalOcean personal access, OAuth or refresh token",
           ("dop_v1_", "doo_v1_", "dor_v1_"), r"do[pro]_v1_[a-f0-9]{64}",
           source="betterleaks:digitalocean-*"),
    Format("shopify-token", "a Shopify access token or shared secret",
           ("shpat_", "shpca_", "shppa_", "shpss_"), r"shp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}",
           source="betterleaks:shopify-*"),
    Format("databricks-token", "a Databricks personal access token",
           ("dapi",), r"dapi[a-f0-9]{32}(?:-[0-9]+)?",
           source="betterleaks:databricks-api-token"),
    Format("hashicorp-vault-token", "a HashiCorp Vault token",
           ("hvs.", "hvb.", "hvr."), rf"hv[sbr]\.{_B64URL}{{24,300}}",
           source="betterleaks:vault-service-token/vault-batch-token; noseyparker"),
    Format("terraform-cloud-token", "a Terraform Cloud API token", (),
           r"(?<![A-Za-z0-9_-])[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9_=-]{60,70}",
           markers=(".atlasv1.",),
           source="betterleaks:hashicorp-tf-api-token"),
    Format("postman-api-key", "a Postman API key",
           ("PMAK-",), r"PMAK-[a-f0-9]{24}-[a-f0-9]{34}",
           source="betterleaks:postman-api-token"),
    Format("private-key-pem", "a PEM-encoded private key", (),
           r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY(?: BLOCK)?-----"
           r"(?:[A-Za-z0-9+/=\s:,]|-(?!----)){64,}"
           r"(?:-----END (?:[A-Z]+ )?PRIVATE KEY(?: BLOCK)?-----)?",
           markers=("-----BEGIN",),
           source="betterleaks:private-key; noseyparker:np.pem.1"),
    Format("age-secret-key", "an age secret key",
           ("AGE-SECRET-KEY-1",), r"AGE-SECRET-KEY-1[A-Z0-9]{58}",
           source="betterleaks:age-secret-key; noseyparker:np.age.2"),

    # ────────────────────────────────────────────────────────────────────────
    # WIDENING TRANCHE — additional prefix-anchored vendor formats.
    # Admission rule, unchanged: a row earns its place with a namespaced prefix
    # (or a fixed marker) that ordinary text does not carry, plus a fixed
    # charset+length. The prefix is what makes a false positive effectively
    # impossible; getting a length loose only under-catches, it never widens to
    # ordinary strings. Anything whose only signal was entropy, a bare hash, a
    # UUID, or a short common word was rejected (see docs/85 / PR notes), not
    # padded in. No checksum is transcribed here beyond GitHub/npm's documented
    # CRC32 above — none of these vendors publish one this module can verify.
    # ────────────────────────────────────────────────────────────────────────

    # cloud / infrastructure ---------------------------------------------------
    Format("alibaba-access-key-id", "an Alibaba Cloud access key ID",
           ("LTAI",), r"LTAI[a-zA-Z0-9]{20}",
           source="betterleaks:alibaba-access-key-id; gitleaks:alibaba-access-key-id"),
    Format("tencent-secret-id", "a Tencent Cloud secret ID",
           ("AKID",), r"AKID[A-Za-z0-9]{32,40}",
           source="gitleaks:tencent-cloud-secret-id"),
    Format("adobe-client-secret", "an Adobe client secret",
           ("p8e-",), r"p8e-[a-zA-Z0-9]{32}",
           source="betterleaks:adobe-client-secret; gitleaks:adobe-client-secret"),

    # package registries / build ----------------------------------------------
    Format("docker-pat", "a Docker personal access token",
           # alnum-only body: a `-`/`_` (a kebab slug, a UUID) ends the run
           # before {27,}, so `dckr_pat_` glued to an image tag never completes.
           ("dckr_pat_",), r"dckr_pat_[A-Za-z0-9]{27,}",
           source="gitleaks:docker-pat"),
    Format("clojars-api-token", "a Clojars deploy token",
           ("CLOJARS_",), r"CLOJARS_[a-zA-Z0-9]{60}",
           source="betterleaks:clojars-api-token; gitleaks:clojars-api-token"),
    Format("rubygems-api-key", "a RubyGems API key",
           ("rubygems_",), r"rubygems_[a-f0-9]{48}",
           source="betterleaks:rubygems-api-token; gitleaks:rubygems-api-token"),

    # AI / ML providers --------------------------------------------------------
    Format("groq-api-key", "a Groq API key",
           ("gsk_",), r"gsk_[A-Za-z0-9]{52}",
           source="gitleaks:groq-api-key"),
    Format("perplexity-api-key", "a Perplexity API key",
           ("pplx-",), r"pplx-[A-Za-z0-9]{48}",
           source="gitleaks:perplexity-api-key"),
    Format("openrouter-api-key", "an OpenRouter API key",
           ("sk-or-v1-",), r"sk-or-v1-[a-f0-9]{64}",
           source="gitleaks:openrouter-api-key"),

    # developer platforms / SaaS ----------------------------------------------
    Format("linear-api-key", "a Linear API key",
           ("lin_api_",), r"lin_api_[a-zA-Z0-9]{40}",
           source="betterleaks:linear-api-key; gitleaks:linear-api-key"),
    Format("figma-token", "a Figma personal access token",
           ("figd_",), r"figd_[A-Za-z0-9]{40,}",
           source="betterleaks:figma-pat; gitleaks:figma-pat"),
    Format("typeform-token", "a Typeform API token",
           ("tfp_",), r"tfp_[A-Za-z0-9]{44,}",
           source="betterleaks:typeform-api-token; gitleaks:typeform-api-token"),
    Format("notion-token", "a Notion integration token",
           ("ntn_",), r"ntn_[A-Za-z0-9]{40,}",
           source="gitleaks:notion-token"),
    Format("sourcegraph-token", "a Sourcegraph access token",
           ("sgp_",), r"sgp_(?:[a-fA-F0-9]{16,}_)?[a-fA-F0-9]{40}",
           source="betterleaks:sourcegraph-access-token; gitleaks:sourcegraph-access-token"),
    Format("atlassian-token", "an Atlassian API token",
           ("ATATT3xFfGF0",), r"ATATT3xFfGF0[A-Za-z0-9_+/=-]{180,}",
           source="betterleaks:atlassian-api-token; gitleaks:atlassian-api-token"),

    # databases / backends -----------------------------------------------------
    Format("supabase-token", "a Supabase personal access token",
           ("sbp_",), r"sbp_[a-f0-9]{40}",
           source="gitleaks:supabase-token"),
    Format("planetscale-token", "a PlanetScale token",
           ("pscale_tkn_", "pscale_pw_", "pscale_oauth_"),
           r"pscale_(?:tkn|pw|oauth)_[A-Za-z0-9]{32,}",
           source="betterleaks:planetscale-*; gitleaks:planetscale-password/oauth-token"),
    Format("datastax-astra-token", "a DataStax Astra token", (),
           r"AstraCS:[A-Za-z0-9]{20,24}:[a-f0-9]{64}",
           markers=("AstraCS:",),
           source="gitleaks:datastax-astra-token"),

    # observability / monitoring ----------------------------------------------
    Format("newrelic-key", "a New Relic API key",
           ("NRAK-", "NRJS-", "NRII-", "NRRA-", "NRMA-", "NRAA-"),
           r"NR(?:AK|JS|II|RA|MA|AA)-[A-Za-z0-9]{19,33}",
           source="betterleaks:new-relic-*; gitleaks:new-relic-user-api-key"),
    Format("sentry-token", "a Sentry auth token",
           ("sntrys_", "sntryu_"), r"sntry[su]_[A-Za-z0-9]{40,}",
           source="betterleaks:sentry-org-auth-token; gitleaks:sentry-org-auth-token"),
    # Only the fixed-structure `glsa_` (32 alnum + `_` + 8 hex) is kept; the
    # `glc_` cloud token is an unbounded standard-base64 blob with no internal
    # structure — indistinguishable from `glc_` glued to an ordinary base64
    # string without an entropy measure, which this module does not have — so
    # it is deferred, not shipped loose.
    Format("grafana-token", "a Grafana service-account token",
           ("glsa_",), r"glsa_[A-Za-z0-9]{32}_[a-fA-F0-9]{8}",
           source="betterleaks:grafana-*; gitleaks:grafana-service-account-token"),
    Format("dynatrace-token", "a Dynatrace API token",
           ("dt0c01.",), r"dt0c01\.[A-Z0-9]{24}\.[A-Z0-9]{64}",
           source="betterleaks:dynatrace-api-token; gitleaks:dynatrace-api-token"),

    # payments / logistics -----------------------------------------------------
    Format("square-token", "a Square access token or secret",
           ("sq0atp-", "sq0csp-"), r"sq0(?:atp|csp)-[A-Za-z0-9]{22,43}",
           source="betterleaks:square-*; gitleaks:square-access-token/secret"),
    Format("paypal-braintree-token", "a PayPal/Braintree access token", (),
           r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}",
           markers=("access_token$production$",),
           source="betterleaks:paypal-braintree-access-token; gitleaks:paypal-braintree-access-token"),
    Format("razorpay-key-id", "a Razorpay live key ID",
           ("rzp_live_",), r"rzp_live_[a-zA-Z0-9]{14}",
           source="gitleaks:razorpay-*, live keys only by decision"),
    Format("easypost-key", "an EasyPost production API key",
           ("EZAK",), r"EZAK[a-zA-Z0-9]{54}",
           source="betterleaks:easypost-api-token; gitleaks:easypost-api-token"),
    Format("shippo-token", "a Shippo live API token",
           ("shippo_live_",), r"shippo_live_[a-f0-9]{40}",
           source="gitleaks:shippo-api-token, live keys only by decision"),
    Format("sendinblue-key", "a Brevo (Sendinblue) API key",
           ("xkeysib-",), r"xkeysib-[a-f0-9]{64}-[a-zA-Z0-9]{16}",
           source="betterleaks:sendinblue-api-token; gitleaks:sendinblue-api-token"),
    Format("amazon-mws-token", "an Amazon MWS auth token", (),
           r"amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
           markers=("amzn.mws.",),
           source="betterleaks:amazon-mws-auth-token; gitleaks:amazon-mws-auth-token"),

    # infra-as-code / secrets platforms ---------------------------------------
    # NB: pulumi (`pul-` + 40 hex) was REJECTED here — `pul-` is a plausible
    # hyphenated fragment and 40 lowercase hex is SHA-1-shaped, so `git checkout
    # -b pul-<sha1>` would fire. A short, common-looking prefix in front of a
    # bare-hash body does not clear the false-positive floor.
    Format("doppler-token", "a Doppler token",
           ("dp.pt.", "dp.st.", "dp.ct.", "dp.sa.", "dp.scim.", "dp.audit."),
           r"dp\.(?:pt|st|ct|sa|scim|audit)\.[a-zA-Z0-9]{40,44}",
           source="betterleaks:doppler-api-token; gitleaks:doppler-api-token"),
    Format("sonarqube-token", "a SonarQube token",
           ("sqp_", "squ_", "sqa_"), r"sq[pua]_[a-f0-9]{40}",
           source="gitleaks:sonarqube-token"),
    Format("tailscale-key", "a Tailscale key",
           ("tskey-auth-", "tskey-api-", "tskey-client-"),
           r"tskey-(?:auth|api|client)-[A-Za-z0-9]{10,}-[A-Za-z0-9]{20,}",
           source="gitleaks:tailscale-key"),

    # webhooks / signing -------------------------------------------------------
    Format("discord-webhook-url", "a Discord webhook URL", (),
           r"https://discord(?:app)?\.com/api/webhooks/[0-9]{17,20}/[A-Za-z0-9_-]{60,68}",
           markers=("discord.com/api/webhooks/", "discordapp.com/api/webhooks/"),
           source="gitleaks:discord-webhook-url"),
    Format("stripe-webhook-secret", "a Stripe webhook signing secret",
           ("whsec_",), r"whsec_[a-zA-Z0-9]{32,}",
           source="stripe.com/docs: webhook signing secret (whsec_)"),
    # ── Sting's own. A device token posts records into its org; an enrolment
    # string mints device tokens. Read from their source, not guessed. ──
    Format("sting-device-token", "a Sting device token",
           ("sting_dev_",), rf"sting_dev_{_B64URL}{{43}}",
           source="the collector's enrolment DEVICE_TOKEN_PREFIX (#21): "
                  "`sting_dev_` + secrets.token_urlsafe(32), 53 characters"),
    Format("sting-enrolment", "a Sting enrolment string",
           (_ENROL_PREFIX,), rf"sting-enrol-v1\.{_B64URL}{{16,4081}}={{0,2}}",
           check="sting-enrolment-payload",
           source="installer/enrol.py PREFIX and decode(); MAX_STRING 4096"),
)

# ⚠ PLACEHOLDERS ARE EXCLUDED BY SHAPE, NOT BY RANDOMNESS. A documentation key
# says EXAMPLE in it; a template says xxxx or YOUR_; a copied-and-blanked key
# is one character repeated. None of these needs a randomness measure to see.
_PLACEHOLDER_WORDS = ("example", "xxxx", "your_", "placeholder", "changeme",
                      "redacted", "dummy")
_KNOWN_DOC_VALUES = ("sk_live_a2V5Xz",)          # Stripe's documentation key


def _is_placeholder(value: str, prefix: str) -> bool:
    """A documentation or template value, told apart by SHAPE alone."""
    lowered = value.lower()
    if any(word in lowered for word in _PLACEHOLDER_WORDS):
        return True
    if any(value.startswith(doc) for doc in _KNOWN_DOC_VALUES):
        return True
    body = value[len(prefix):]
    if len(set(body)) <= 3:
        return True                            # AKIAXXXXXXXXXXXXXXXX, ghp_0000…
    return all(ord(b) - ord(a) == 1 for a, b in zip(body, body[1:]))  # ABCDEF…


# ── compiled once at import ────────────────────────────────────────────────────
_COMPILED = {f.id: re.compile(f.shape) for f in FORMATS}
_TOKEN_FORMATS = tuple(f for f in FORMATS if f.prefixes)
_TEXT_FORMATS = tuple(f for f in FORMATS if f.markers)
_BY_PREFIX: dict[str, tuple[Format, ...]] = {}
for _f in _TOKEN_FORMATS:
    for _p in _f.prefixes:
        _BY_PREFIX[_p] = _BY_PREFIX.get(_p, ()) + (_f,)
_PREFIX_LENGTHS = tuple(sorted({len(p) for p in _BY_PREFIX}))
_TRIGGERS = tuple(sorted(set(_BY_PREFIX) | {m for f in _TEXT_FORMATS for m in f.markers}))


def _validates(fmt: Format, value: str, prefix: str = "") -> bool:
    if _is_placeholder(value, prefix):
        return False
    check = _CHECKS.get(fmt.check) if fmt.check else None
    return check(value) if check else True


def _shape_hits(text: str, bound: int | None = None) -> list[Hit]:
    """Token-level formats whose shape sits in `text`, at every occurrence of
    its prefix that starts at or before `bound` (anywhere, by default);
    offsets are into `text`."""
    limit = len(text) if bound is None else bound
    hits = []
    for prefix, formats in _BY_PREFIX.items():
        at = text.find(prefix, 0, limit + len(prefix))
        while at != -1:
            for fmt in formats:
                match = _COMPILED[fmt.id].match(text, at)
                if match is None:
                    continue
                end = match.end()
                # A key glued to further alphanumerics is a longer string
                # that merely begins like one — `ghp_<36>abc` is not a token.
                if end < len(text) and text[end].isalnum():
                    continue
                if _validates(fmt, match.group(0), prefix):
                    hits.append(Hit(fmt.id, fmt.name, at, end))
            at = text.find(prefix, at + 1, limit + len(prefix))
    return hits


def _text_hits(text: str, bound: int | None = None, *,
               placeholder_hides: bool = True) -> list[Hit]:
    """The text-level formats: every block or URL that starts at or before
    `bound` (anywhere, by default), searched from its marker.

    ⚠ `placeholder_hides`: A FORMAT WHOSE FIRST MATCH IS A PLACEHOLDER
    CONTRIBUTES NOTHING, as before. The one-hit matcher searched once per
    format and moved on, so a real block after a documentation block was never
    a hit, and reading on would be a new detection. The evidence mask reads on
    (`masked_spans`): hiding a real block moves no verdict."""
    limit = len(text) if bound is None else bound
    hits = []
    for fmt in _TEXT_FORMATS:
        if not any(text.find(m, 0, limit + _MARKER_REACH + len(m)) != -1
                   for m in fmt.markers):
            continue
        for index, match in enumerate(_COMPILED[fmt.id].finditer(text)):
            if match.start() > limit:
                break
            if _validates(fmt, match.group(0)):
                hits.append(Hit(fmt.id, fmt.name, match.start(), match.end()))
            elif index == 0 and placeholder_hides:
                break
    return hits


_MARKER_REACH = 64
"""How far into a text-level value its marker can sit: a webhook URL's is
eight characters in, a Terraform token's fourteen; the rest start with it. A
search for a value that starts by some position looks for its marker only
this far past it. Pinned by tests/test_known_formats_all_matches.py."""


def _unglued(text: str) -> tuple[str, list[int]]:
    """`text` without shell quotes and escapes, and where they were."""
    removed = [m.start() for m in _SHELL_GLUE.finditer(text)]
    return _SHELL_GLUE.sub("", text), removed


def _count_below(positions: list[int], limit: int) -> int:
    """How many of the ascending `positions` are below `limit`, by halving."""
    lo, hi = 0, len(positions)
    while lo < hi:
        mid = (lo + hi) // 2
        if positions[mid] < limit:
            lo = mid + 1
        else:
            hi = mid
    return lo


def _raw_offset(stripped_offset: int, removed: list[int]) -> int:
    """The raw-text position of a stripped-text position: walk the removed
    positions (ascending) and shift past each one that sits before it."""
    raw = stripped_offset
    for position in removed:
        if position <= raw:
            raw += 1
        else:
            break
    return raw


_RANK = {f.id: i for i, f in enumerate(FORMATS)}

def _outside(glued: list[Hit], plain: list[Hit]) -> list[Hit]:
    """The glue-pass hits that overlap no first-pass hit, in one sweep over
    both sorted: either list can hold thousands, and a pairwise check cost a
    quoted text packed with keys over a second (security review)."""
    merged: list[tuple[int, int]] = []
    for start, end in sorted((h.start, h.end) for h in plain):
        if merged and start < merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    kept, i = [], 0
    for hit in sorted(glued, key=lambda h: h.start):
        while i < len(merged) and merged[i][1] <= hit.start:
            i += 1
        if i < len(merged) and merged[i][0] < hit.end:
            continue
        kept.append(hit)
    return kept


def _scannable(text: str | None) -> str | None:
    """What the matcher reads of `text`: its first `MAX_SCAN` characters, or
    None when it is empty or holds no trigger. The prefilter, unchanged: a text
    with no trigger costs what it cost."""
    if not text:
        return None
    if len(text) > MAX_SCAN:
        text = text[:MAX_SCAN]
    if not any(trigger in text for trigger in _TRIGGERS):
        return None
    return text


def _candidates(text: str, bound: int | None = None, *,
                placeholder_hides: bool = True) -> list[Hit]:
    """Every match in `text` that starts at or before `bound` (anywhere, by
    default), overlaps included: the first pass's, then the glue-stripped
    pass's that overlap none of them, offsets into the text as given.

    ⚠ A VALUE THE FIRST PASS FOUND IS FOUND. The second pass is for what glue
    hid from the first. Its offsets are mapped exactly as before: a glued
    value's end lands past a quote that closes right after it, so its stand-in
    covers that quote too, as it always has; the same QUOTED value read by
    both passes would otherwise end one character late."""
    limit = len(text) if bound is None else bound
    plain = (_shape_hits(text, limit)
             + _text_hits(text, limit, placeholder_hides=placeholder_hides))
    if _SHELL_GLUE.search(text) is None:
        return plain
    stripped, removed = _unglued(text)
    cut = limit - _count_below(removed, limit)
    glued = [Hit(h.format_id, h.name, _raw_offset(h.start, removed),
                 _raw_offset(h.end, removed))
             for h in _shape_hits(stripped, cut)
             + _text_hits(stripped, cut, placeholder_hides=placeholder_hides)]
    return plain + _outside(glued, plain)


def _by_position(hits: list[Hit]) -> list[Hit]:
    """Every match once, leftmost start first, then the longest, then the
    table's order."""
    return sorted(set(hits), key=lambda h: (h.start, h.start - h.end,
                                            _RANK[h.format_id]))


def _in_order(hits: list[Hit]) -> list[Hit]:
    """Position order, one hit per value: where two matches overlap, the one
    `_by_position` puts first."""
    kept: list[Hit] = []
    for hit in _by_position(hits):
        if not kept or hit.start >= kept[-1].end:
            kept.append(hit)
    return kept


def find_known_secrets(text: str | None) -> list[Hit]:
    """Every documented credential shape in `text`, in position order.

    ⚠ ALL OF THEM, AND IN THE TEXT'S ORDER. The one-hit matcher ran the token
    formats before the text-level ones, each in table order, and the
    glue-stripped pass only when the first found nothing — so in a text with
    two values it could return the LATER one, and the evidence masked only
    that one: the other sat raw in the local record (a Stripe-live-format
    value, in a real export). Both passes run now, so a glued value beside a
    plain one is found too.

    Deterministic and cheap on the common path: a text containing none of the
    ~100 literal triggers returns after the prefilter, exactly as before.
    Offsets are always into the text as given, including through the second,
    glue-stripped pass. Reads every value, so nothing on the hot path asks it.
    """
    scanned = _scannable(text)
    return _in_order(_candidates(scanned)) if scanned is not None else []


def holds_known_secret(text: str | None) -> bool:
    """Does `text` hold any documented credential shape? The yes or no the
    engine asks on EVERY action (`credentials.carries_secret`).

    ⚠ THE ONE-HIT MATCHER, UNCHANGED, FOR ITS COST AS MUCH AS ITS ANSWER. It
    stops at the first valid match in table order, and runs the glue-stripped
    pass only when the first found nothing. Which value comes FIRST in the text
    is `find_known_secret`'s question, and answering it can take the whole walk:
    a key at the end of 128 KB of triggers cost 10.7 ms that way, where this
    answers in about one (security review)."""
    scanned = _scannable(text)
    if scanned is None:
        return False
    if _any_hit(scanned):
        return True
    return _SHELL_GLUE.search(scanned) is not None and _any_hit(_unglued(scanned)[0])


def _any_hit(text: str) -> bool:
    """The one-hit matcher's question as it asked it: the token formats in
    table order, then each text-level format's first match; the first valid
    one ends it."""
    for prefix, formats in _BY_PREFIX.items():
        at = text.find(prefix)
        while at != -1:
            for fmt in formats:
                match = _COMPILED[fmt.id].match(text, at)
                if match is None:
                    continue
                end = match.end()
                if end < len(text) and text[end].isalnum():
                    continue
                if _validates(fmt, match.group(0), prefix):
                    return True
            at = text.find(prefix, at + 1)
    for fmt in _TEXT_FORMATS:
        if not any(marker in text for marker in fmt.markers):
            continue
        found = _COMPILED[fmt.id].search(text)
        if found and _validates(fmt, found.group(0)):
            return True
    return False


def find_known_secret(text: str | None) -> Hit | None:
    """The leftmost documented credential shape in `text`, or None: the value
    the reason names and the evidence points at, asked once an action is found
    to carry one (`holds_known_secret` answers yes or no on every action).

    It is None exactly when that answer is no. Only WHICH value changed: the
    leftmost now, where it used to be the first in table order.

    ⚠ NOT BY READING EVERY VALUE. Each prefix is searched only up to the
    leftmost start found so far, which reads every match at that position and
    none that could not be first: a text packed with keys costs what its first
    one costs (security review). Its ceiling is the one-hit matcher's walk over
    the same text with its value removed."""
    scanned = _scannable(text)
    if scanned is None:
        return None
    plain = _first_shape_hits(scanned, len(scanned))
    bound = min((h.start for h in plain), default=len(scanned))
    plain += _first_text_hits(scanned, bound)
    bound = min((h.start for h in plain), default=len(scanned))
    if _SHELL_GLUE.search(scanned) is not None:
        stripped, removed = _unglued(scanned)
        # The stripped text's position of `bound`: a glued match that starts
        # later cannot be the leftmost.
        cut = bound - _count_below(removed, bound)
        found = _first_shape_hits(stripped, cut)
        found += _first_text_hits(stripped, min((h.start for h in found), default=cut))
        plain += _outside([Hit(h.format_id, h.name, _raw_offset(h.start, removed),
                               _raw_offset(h.end, removed)) for h in found], plain)
    hits = _in_order(plain)
    return hits[0] if hits else None


def _first_shape_hits(text: str, bound: int) -> list[Hit]:
    """Each prefix's first valid match starting at or before `bound`, with
    `bound` narrowed to the leftmost found so far: every match at the leftmost
    position is read, and a prefix is never searched past where it could
    still be first. A text packed with keys costs what its first one costs."""
    hits = []
    for prefix, formats in _BY_PREFIX.items():
        at = text.find(prefix, 0, bound + len(prefix))
        while at != -1:
            matched = False
            for fmt in formats:
                match = _COMPILED[fmt.id].match(text, at)
                if match is None:
                    continue
                end = match.end()
                if end < len(text) and text[end].isalnum():
                    continue
                if _validates(fmt, match.group(0), prefix):
                    hits.append(Hit(fmt.id, fmt.name, at, end))
                    bound = min(bound, at)
                    matched = True
            if matched:
                break
            at = text.find(prefix, at + 1, bound + len(prefix))
    return hits


def _first_text_hits(text: str, bound: int) -> list[Hit]:
    """Each text-level format's first match, when it starts at or before
    `bound` and is not a placeholder (the rule `_text_hits` keeps)."""
    hits = []
    for fmt in _TEXT_FORMATS:
        reach = bound + _MARKER_REACH
        if not any(text.find(m, 0, reach + len(m)) != -1 for m in fmt.markers):
            continue
        first = _COMPILED[fmt.id].search(text)
        if first is not None and first.start() <= bound and _validates(fmt, first.group(0)):
            hits.append(Hit(fmt.id, fmt.name, first.start(), first.end()))
    return hits


def stand_in(name: str, length: int) -> str:
    """What stands where a value sat in evidence: `<an AWS access key ID, 20
    chars>` — what it was, never what it said."""
    return f"<{name}, {length} chars>"


BACK_SCAN = 16 * 1024
"""How far `hidden_before` reads back from the value a reason names. ⚠ #75's
LOW: it read `MAX_SCAN` (128 KB) back, ~9.6 ms on the hook, for an action
already carrying a secret. Every text-level format but a PEM private key is a
few hundred characters at most, and a PEM key of RSA-16384 is under 13 KB, so
16 KB holds any block's start; past it, `_cut_blocks` masks on doubt."""

_BODY_RUN = re.compile(r"(?:[A-Za-z0-9+/=\s:,]|-(?!----))+")
"""A maximal run of a PEM body's characters (the `private-key-pem` pattern's
body class): what is left of a block the bound cut, the one shape that can
start before `BACK_SCAN` and still reach the window. Read as MAXIMAL runs, so
each character is read once: a pattern asking for 64 from every position read
a text of 63-character runs 63 times (8 ms at the bound, python review)."""
_BODY_MIN = 64
"""The fewest body characters the `private-key-pem` pattern takes."""
_END_LINE = re.compile(r"-----END (?:[A-Z]+ )?PRIVATE KEY(?: BLOCK)?-----")
_PEM_NAME = next(f.name for f in FORMATS if f.id == "private-key-pem")


def hidden_before(text: str, first: Hit, reach: int) -> list[tuple[int, int, str]]:
    """Real text-level blocks that end in the `reach` characters before
    `first`, as `(start, end, name)`.

    ⚠ THE WINDOW'S LEFT SIDE (security review, round three). A block behind a
    placeholder of its own format is never a candidate for `first` (the
    one-hit rule keeps it so), yet a window around `first` shows its tail, and
    that tail stayed raw, on main too. Only such a block can end there: any
    other value before `first` would have been first.

    ⚠ READ BACK `BACK_SCAN` CHARACTERS, AND MASK ON DOUBT AT THE BOUND. A
    block that started before the bound has no BEGIN in what is read, so it is
    not found; its body is an unbroken run of `_BODY_RUN`'s characters up to
    the window. So when the bound cuts the text, EVERY such run that reaches
    the window is hidden: a tail the unbounded scan hid is never shown.
    ⚠ ANY RUN, NOT ONE STARTING AT THE BOUND (security review, HIGH): a bound
    on a `-----` byte of a marker line started no run, and the tail showed."""
    lo = max(0, first.start - BACK_SCAN)
    found = [(lo + hit.start, lo + hit.end, hit.name)
             for hit in _text_hits(text[lo:first.start], placeholder_hides=False)
             if lo + hit.end > first.start - reach]
    if lo > 0:
        found += _cut_blocks(text, lo, first.start, reach)
    return found


def _cut_blocks(text: str, lo: int, end: int, reach: int) -> list[tuple[int, int, str]]:
    """Every run of a PEM body's characters between `lo` and `end`, with the
    END line right after it, that is long enough to be a block's and reaches
    the `reach` characters before `end`: what the bound may have cut."""
    found = []
    for run in _BODY_RUN.finditer(text, lo, end):
        tail = _END_LINE.match(text, run.end(), end)
        # ⚠ AN END LINE RIGHT AFTER IT IS REASON ENOUGH, WHATEVER ITS LENGTH
        # (python review, round two): masked on doubt.
        if tail is None and run.end() - run.start() < _BODY_MIN:
            continue
        stop = tail.end() if tail else run.end()
        if stop > end - reach:
            found.append((run.start(), stop, _PEM_NAME))
    return found


def masked_spans(text: str, first: Hit, reach: int) -> list[tuple[int, int, str]]:
    """What an evidence window around `first` must hide: every match that can
    show in a window reaching `reach` characters past it, overlapping ones
    merged into one span, as `(start, end, name)` in the text as given; the
    first span is `first`'s own.

    ⚠ OVERLAPS ARE MASKED WHOLE. One value per overlap is enough for the
    reason and the offset; the mask needs them all, or a GitLab-shaped token
    whose tail is a PEM header hides the private key behind it (security
    review). Every block is masked, even one after a placeholder: hiding it
    moves no verdict.

    ⚠ READ FROM `first` ON, so a value past the scan bound that the window
    reaches is found too. ⚠ AND ONLY AS FAR AS THE WINDOW REACHES: `reach`
    characters of the MASKED text after the first stand-in, counting each later
    value as its `stand_in`. A text packed with values costs what a window can
    show, not what the text holds."""
    base = first.start
    tail = text[base:base + MAX_SCAN]
    bound = first.end - base + reach
    while True:
        spans = [(0, first.end - base, first.name)]
        for hit in _by_position(_candidates(tail, bound, placeholder_hides=False)):
            if hit.start < spans[-1][1]:
                spans[-1] = (spans[-1][0], max(spans[-1][1], hit.end), spans[-1][2])
            else:
                spans.append((hit.start, hit.end, hit.name))
        cover, room = spans[0][1], reach
        for start, end, name in spans[1:]:
            if start - cover >= room:
                break
            room -= start - cover
            shown = len(stand_in(name, end - start))
            cover, room = end, max(room - shown, 0)
            if room == 0:
                break
        cover += room
        if cover <= bound:
            return [(base + start, base + end, name) for start, end, name in spans]
        bound = cover
