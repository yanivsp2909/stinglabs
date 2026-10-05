# Engine docs

| doc | what it covers |
|---|---|
| [24-adapter-contract.md](24-adapter-contract.md) | writing an adapter for a new coding agent: the three functions, what the engine never trusts an adapter for, the conformance suite |
| [ENGINE_LAYOUT.md](ENGINE_LAYOUT.md) | where each rule lives in `core/`, and which files a change touches |

User-facing guides (install, uninstall, configuration, Sparta, agents) are in the repository's top-level
[`docs/`](../../docs/).

Comments in the code cite numbered design records (`docs/36`, `docs/107` and so on) and a development log
(`PROGRESS.md`). Those are the maintainers' internal working notes, which include measurements taken on real
sessions, and they are not published. Where a test depends on one, it skips and says so.
