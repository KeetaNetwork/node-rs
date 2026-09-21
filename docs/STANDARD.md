# Documentation Standard

## Abstract

This page is the documentation contract for the `node-rs` workspace. It states what belongs in a documentation page. It also fixes the prose, the register, and the page shape.

## Purpose

An engineer reads this page before writing or reviewing documentation in this repository. After reading, the engineer can tell whether a page belongs in the tree. The engineer can also write the page in the expected prose and shape.

## Requirements Language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC 2119](https://datatracker.ietf.org/doc/html/rfc2119) [RFC 8174](https://datatracker.ietf.org/doc/html/rfc8174) when, and only when, they appear in all capitals, as shown here.

This page is the one home for that declaration. Other pages in this tree MAY use those keywords under this home. They MUST NOT repeat this section.

## The inclusion test

Documentation earns its maintenance cost by holding the knowledge that lives outside any one file. A page MUST carry at least one of the following.

- An invariant that spans several files, which puts it beyond the reach of a single file.
- A decision and the alternative it rejected, so a later reader keeps it closed.
- A contract that binds consumer behavior, such as a feature gate or a signing rule.
- A procedure an operator runs under pressure.

A page MUST NOT carry the following. The source is the one correct home for each one.

- Barrel maps, export lists, or directory listings.
- Field tables that repeat crate rustdoc without adding operator semantics.
- One crate-root README that only restates that crate `Cargo.toml` and `pub use`.
- A product Architecture page for `keetanetwork-node` or `keetanetwork-ledger` while those crates remain empty stubs.
- A decision log, a changelog of past reviews, or a ticket or phase diary.

One body of knowledge takes one page as its home. A second page that needs it MUST link to that home rather than restate it. The [Overview](README.md) names the living pages.

[Architecture](ARCHITECTURE.md) holds the workspace collaboration graph and the interaction path. Product-crate architecture lives under that crate `docs/ARCHITECTURE.md`. That page MUST add collaboration or feature-gate substance that rustdoc on a single type cannot hold. It MUST NOT restate that crate `pub use` list. The [Overview](README.md) is the table of contents into those paths.

A crate `docs/README.md` MAY stay a thin pointer into that crate `docs/ARCHITECTURE.md`. A stub crate MAY carry a minimal `docs/README.md` that names the reserved crate. It MUST NOT carry a product Architecture page.

A concept page under `docs/concepts/` lands only when it still holds a non-rustdoc invariant after the workspace Architecture draft and the crate architecture. A candidate that collapses to a field list MUST NOT land.

When a page must name a symbol, it cites that symbol as `Symbol` in `path/to/file`. The source carries its own detail.

## Prose

A page uses full sentences and keeps their articles. A sentence holds one topic. A sentence does not join independent clauses with a semicolon. Prose uses the active voice and the present tense.

A page uses the exact technical noun, in code font, on every mention of the same thing. A page uses the ASCII hyphen only and writes each relation as words. A page prefers a table, a list, or a diagram when that form reorganizes substance.

A page states contracts in the positive. A page names the command or path that Makefile, Cargo.toml, rust-toolchain.toml, or the cited source file states.

Each register addresses its reader differently. A page MUST hold one register throughout.

| Register | Reader | Voice |
| --- | --- | --- |
| Concept | An engineer building a model of the system | Third person, declarative |
| Implementation | An engineer integrating the software into a service | Second person, imperative |
| Operations | An operator under time pressure | Second person, imperative, one action per step |
| Reference | An engineer checking an exact contract | Third person, terse, declarative |

## Page shape

Every shaped page under workspace `docs/` and every crate `docs/ARCHITECTURE.md` MUST carry the following sections, in the following order.

1. **Title.** The subject of the page, as a noun phrase.
2. **Abstract.** Two or three sentences on what the page holds.
3. **Purpose.** Who reads the page, and what they can do afterward.
4. **Body.** The sections that carry the content, which SHOULD sit in the correct dependency order.
5. **Falsified by.** The changes that make the page wrong.

The closing section is the maintenance contract. It MUST name the code or tree changes that invalidate the page.

A page SHOULD cite the test or rustdoc example that encodes an invariant when that file is the enforcement point. One citation replaces a prose argument that the guarantee holds.

The root `README.md` and each crate `docs/README.md` MAY stay a thin pointer. Those pages do not use this page shape. They MUST NOT redeclare Requirements Language.

Navigation and audience live on the [Overview](README.md). This page MUST NOT carry a page index.

A Mermaid diagram, when used, MUST give every node and participant an id that is not a Mermaid keyword. Ids such as `crate_account` and `crate_client` stay keyword-safe. A bare id `graph`, `end`, or `subgraph` is invalid.

## rustdoc comments

A `///` comment MUST add signal that the signature cannot carry. It MUST NOT narrate the next line. It MUST NOT add a historical aside. Happy-path comments MUST state the contract in the positive.

Public surfaces that already have rustdoc examples MUST keep a short snippet. Full flows belong as GitHub line links into tests in the repository. This tree MUST NOT invent an `examples/` directory.

## Falsified by

A change to the prose contract, to the inclusion test, or to the page shape.
