# MintGuard — a read-only screening agent for BSC mints

**Live demo:** https://costa-incident-fruits-continues.trycloudflare.com
**API:** `GET /check?input=<url-or-0x-address>` · `GET /health`

MintGuard answers one question *before* any wallet signs anything:

> **Is this mint what it claims to be — and is it safe to touch?**

Give it a mint page URL or a BSC contract address. It identifies the real
contract, reads price / quota / supply / pause / open state live from the
chain, verifies the Agent ID gate against the real SPACE ID registry,
simulates the mint call at value 0, fingerprints the contract against an
experience database of past mints, and returns a structured verdict with
plain-language warnings.

## Use case

The Binance Agent ID ecosystem produced a wave of gated free mints, claims
and fair sales through late 2026. Most are redeploys of a handful of
contract families — but mixed in are traps: fake Agent ID gates that are
not the real registry, voucher/signature requirements hidden behind a
"free" label, exhausted free pools, upgradeable proxies whose terms can
change after you mint, and owners who can pause or reprice at will.

A human (or an autonomous minting agent) typically has minutes to decide.
Checking all of this by hand means an explorer, a Sourcify lookup, manual
getter calls and a simulation — per project, per wallet. MintGuard does
that whole pass in seconds and returns a verdict an operator can act on:
`CANDIDATE_FREE`, `PAID`, `CLOSED_OR_SOLDOUT`, and more, each with the
warnings that matter.

It is built for airdrop hunters, agent operators running gated-mint
workflows, and anyone who has been burned by a mint that was not what the
landing page claimed.

## What it checks

1. **Contract identification** — resolves a URL to candidate contracts
   (keeps only addresses with code and mint-like functions), or takes an
   address directly. Reads code size, codehash and EIP-1967 proxy slots
   (implementation + admin), so an upgradeable proxy is called out.
2. **Live state, not project claims** — a table of common getters for
   supply, price, per-wallet quota, pause and open flags, queried in
   parallel from public BSC RPCs.
3. **Gate verification** — detects an Agent ID gate and compares it
   against the real SPACE ID registry (`0x60B9262456dE011F7d15a54CdD8c48bAaa8B022F`).
   A gate that merely *looks* like the registry is flagged.
4. **Dry-run simulation** — candidate mint calls are simulated with
   `eth_call` from the wallet at value 0; the outcome (or the revert
   selector) is recorded.
5. **Fingerprint matching** — the contract's fingerprint (mint function
   selectors + proxy type + gate traits) is matched against a local
   experience database grown from real mint outcomes, so a redeploy of a
   known family — an AgentLaunch-style sale, a proof-of-work mint, a
   voucher-gated claim — is recognised on sight, including its known
   failure modes. Live values are always re-read: a redeploy can change
   every parameter while keeping the same code shape.
6. **Verdict + warnings** — a structured JSON verdict plus human-readable
   warnings (unverified source, live owner, proxy upgradeability,
   signature requirements, exhausted pool, …).

## Example (live output)

`GET /check?input=0x86956Bc830EB62110820Ae79164BeF61c7E31936` (a finished
NFT mint), 2026-11-21:

```json
{
  "agent": "MintGuard",
  "verdict": "CLOSED_OR_SOLDOUT",
  "warnings": ["Owner is set (not renounced): the owner may pause or change terms."],
  "history_match": {"score": 0.7}
}
```

The full response also carries the complete engine report under `report`
(stages with timings, getters, gate analysis, simulations) — the receipts
behind the verdict. A full scan takes ~5–60 seconds depending on RPC
latency; `/health` and this page answer instantly.

## Build context

- **Engine first, API second.** The core is a single-file, dependency-free
  Python engine (`engine/scripts/bsc_mint_precheck.py`, ~870 lines,
  stdlib only — including its own Keccak-256) that has been in daily
  production use inside an Agent ID mint workflow since October 2026.
  `mintguard.py` is a thin stdlib HTTP wrapper: input validation, per-IP
  pacing, a concurrency cap, subprocess isolation with a timeout, and a
  compact summary in front of the full report.
- **Read-only by construction.** There is no signing, approval or payment
  code path anywhere in the engine or the service — not "disabled", but
  absent. MintGuard can look; it cannot touch funds. That is the core
  design decision: a screening agent should never need a key.
- **Experience database.** `learn` records the outcome of every real mint
  attempt (pattern, method, failure reasons) into SQLite. The production
  database is private (it maps an operator's own mint history); this repo
  ships the seed file instead — run `init-db` to build a starter database,
  then grow your own.
- **Hosting.** The demo runs on a small VPS (systemd service +
  Cloudflare tunnel). The tunnel URL is stable while the service runs;
  the code is the deliverable and can be re-hosted anywhere Python 3 runs.

## Limitations

- BSC only, today. The getter table and gate checks are BSC/Agent ID
  specific; other chains need their own registry anchors.
- URL resolution is best-effort: pages that render the contract only
  after heavy JavaScript may need the address pasted directly.
- A `CANDIDATE_FREE` verdict means "passed this precheck", not "safe" —
  execution decisions still belong to the operator.

## Roadmap

- Anchor verdict hashes to zkVerify so a screening result becomes a
  checkable claim ("this contract was screened at time T with verdict V")
  without revealing the operator's full history.
- More chains and more gate registries as the Agent ID pattern spreads.

---

*Submitted to the zkVerify Agent Games, Season 01 — Wildcard track.
Agent link: this repository. Public endpoint: the live demo above.*
