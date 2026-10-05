"""Reads the decision log and POSTs batches to a collector. A SEPARATE PROCESS.

⚠ THE HOOK NEVER TOUCHES THIS, AND THAT IS THE WHOLE DESIGN. The hook decides on
a 12 ms budget on every tool call and writes locally. If it ever waited on a
network, a dead collector — or a slow one, or a captive-portal Wi-Fi that hangs
a TCP connect for 75 seconds — would become latency the developer feels on every
action, and a guard that makes the agent slow is a guard that gets uninstalled.

So the hook writes a file and the shipper reads it. Nothing connects them but the
filesystem. `tests/test_hook_never_ships.py` asserts that hook_entry and core/
import neither this package nor any network module.
"""
