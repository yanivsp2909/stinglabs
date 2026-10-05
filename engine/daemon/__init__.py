"""The resident guard: one process that boots once and decides many times.

    hook_entry.py  ──socket──>  daemon/server.py  ──>  core.engine.decide()

WHY IT EXISTS, IN ONE MEASUREMENT. A hook invocation costs ~50 ms, of which
`engine.decide()` is ~2 ms. The rest is a fresh interpreter and the import of
`core` — paid on every tool call, thrown away at every exit. `decide()` is
already a pure function of `(action, state, world)`, so nothing about it needs a
process of its own; it only needs the process to already be there.

⚠ WHAT THIS PACKAGE MAY NOT DO, AND THE RULES ARE IN daemon/server.py:

    it may not become the only writer          (the fallback path writes too)
    it may not cache session state             (staleness for no measured gain)
    it may not cache the install                (a reinstall must revoke grants)
    it may not decide observe mode              (the client's choke point stays)
    it may not block a tool call by being dead  (the whole of TASK 4)
"""
