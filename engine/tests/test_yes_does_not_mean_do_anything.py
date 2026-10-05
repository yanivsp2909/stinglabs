"""⚠ `--yes` MEANS "DO NOT ASK ME". IT HAS NEVER MEANT "DO ANYTHING".

A walk of the release archive into a clean HOME globally npm-installed
`@anthropic-ai/claude-code` on the machine that ran it, under `--yes`, with no
further consent. On a stranger's machine that is an unconsented change to their
environment made by a SECURITY TOOL on first run — the thing that watches what
your agent installs, installing something. It is the worst possible first
impression this product can make.

⚠ AND IT BREAKS ONE THING, DELIBERATELY. An unattended install on a machine with
NO coding agent used to install one and continue; it now refuses. That is the
right trade — a fleet push to a machine with nothing to guard was guarding
nothing either way — but it IS a behaviour change for a fleet push, and
`test_an_unattended_install_with_no_agent_refuses_rather_than_installing_one`
is where somebody is told.
"""
from __future__ import annotations

from installer import prepare


def _result(**kw):
    base = {"ok": False, "detail": "d", "fix": [["/bin/echo", "did-it"]],
            "fix_note": "a fix"}
    base.update(kw)
    return prepare.Result(**base)


def _apply(results, **kw):
    said, changed = [], []
    outcome = prepare.apply_fixes(results, None, said.append,
                                   changed=changed, **kw)
    return outcome, "\n".join(said), changed


# ════════════════════ the gate ══

def test_a_software_installing_fix_never_runs_unattended(monkeypatch):
    ran = []
    monkeypatch.setattr(prepare, "_run", lambda argv, **k: (ran.append(argv), (0, ""))[1])
    monkeypatch.setattr(prepare, "_recheck", lambda name, scratch: _result(ok=True))

    results = {name: _result(ok=True) for name in prepare.CHECKS}
    results["agent"] = _result(installs_software=True,
                                fix=[["npm", "install", "-g", "an-agent"]],
                                fix_note="install Claude Code")

    _outcome, said, changed = _apply(results, unattended=True)

    assert ran == [], f"a machine-scope fix ran under --yes: {ran}"
    assert "NOT RUN under --yes" in said
    assert "npm install -g an-agent" in said, "the skipped command was not named"
    assert any("NOT done" in line for line in changed)


def test_the_same_fix_does_run_when_a_person_said_yes_at_the_prompt(monkeypatch):
    """⚠ THE GATE IS ON `unattended`, NOT ON THE FIX. Somebody who read the list
    and typed `y` has consented; nothing here second-guesses them."""
    ran = []
    monkeypatch.setattr(prepare, "_run", lambda argv, **k: (ran.append(argv), (0, ""))[1])
    monkeypatch.setattr(prepare, "_recheck", lambda name, scratch: _result(ok=True))

    results = {name: _result(ok=True) for name in prepare.CHECKS}
    results["agent"] = _result(installs_software=True,
                                fix=[["npm", "install", "-g", "an-agent"]])

    _outcome, _said, changed = _apply(results, unattended=False)

    assert ran == [["npm", "install", "-g", "an-agent"]]
    assert "npm install -g an-agent" in changed


def test_a_confined_fix_still_runs_unattended(monkeypatch):
    """A fleet push must still be able to create a directory the operator named
    on the command line. `--yes` is not `--do-nothing`."""
    ran = []
    monkeypatch.setattr(prepare, "_run", lambda argv, **k: (ran.append(argv), (0, ""))[1])
    monkeypatch.setattr(prepare, "_recheck", lambda name, scratch: _result(ok=True))

    results = {name: _result(ok=True) for name in prepare.CHECKS}
    results["scratch"] = _result(fix=[["mkdir", "-p", "/tmp/x"]],
                                  fix_note="create the scratch directory")

    _outcome, _said, changed = _apply(results, unattended=True)

    assert ran == [["mkdir", "-p", "/tmp/x"]]
    assert "mkdir -p /tmp/x" in changed


# ════════════════════ the three that reach outside, named ══

def test_every_fix_that_leaves_our_prefix_is_marked():
    """⚠ THE LIST, ASSERTED. If a new fix is added that installs, downloads or
    reconfigures something outside `~/.sting`, it must be marked — and this is
    the test that fails when it is not.

    Checked by reading the argv of every fix the checks can produce, rather than
    by trusting the flag: a flag that is only compared against itself proves
    nothing.
    """
    reaching = {"npm", "brew", "apt", "apt-get", "yum", "dnf", "pacman",
                 "choco", "winget", "pip", "pip3", "curl", "wget", "port"}

    unmarked = []
    for name, result in prepare.survey().items():
        for argv in result.fix:
            if not argv:
                continue
            tool = str(argv[0]).rsplit("/", 1)[-1].lower()
            if tool in reaching and not result.installs_software:
                unmarked.append((name, argv))
    assert not unmarked, (
        f"these fixes change the machine outside ~/.sting and are NOT marked "
        f"installs_software, so --yes would run them: {unmarked}")


def test_the_flag_defaults_to_false_so_a_new_fix_is_not_silently_exempted():
    """The default is the SAFE-TO-RUN side, which means a careless new fix runs
    under --yes. That is deliberate — the alternative silently disables fixes a
    fleet push needs — and the test above is what catches the careless case."""
    assert prepare.Result(ok=False).installs_software is False
