# Optimizations backlog, ranked by risk to the demo

Candidate improvements to this repo, grouped by **how likely they are to break or change what the demo shows**. Nothing here has been
applied. Items marked *measured* were timed on the dev machine; items marked *reasoned* come from code review and are hypotheses until profiled.

**Risk means:** the chance of breaking the demo, or of changing any number on screen (risk scores, violation counts, evaluation metrics, PDF content).

## Tools that make the riskier items safe

| Guard | What it proves | How |
|---|---|---|
| Byte-identical corpus | Generator/parser refactors changed no data | `python -m synth.generate --out <dir>` from `HEAD` and from the working tree, then `diff -r` |
| Identical evaluation | No metric moved | Re-run `python -m ipsec_analyzer.evaluation`; compare with `docs/EVAL.json` ignoring `generated_at` and `throughput` |
| Identical per-tunnel scores | Scoring/SHAP changes are neutral | Analyze `demo_gateway_audit` before/after; compare every tunnel's risk and anomaly score from `/api/analyses/<id>/tunnels` |
| Backend tests | Core behaviour intact | `python -m pytest tests -q` (14 tests) |
| Browser smoke test | UI still works end to end | Upload, bundled scenario, results, tunnel detail, Evaluation, navigation |
| Fresh-machine run | Install steps still work | Clone, new venv, follow the README |

## Measurements so far

| What | Result | Note |
|---|---|---|
| First analysis after API start (`demo_gateway_audit`) | **5.52 s** | *measured*; model/SHAP load on first use |
| Next analyses of the same capture | **2.05 s, 1.50 s** | *measured* |
| Parse-only / end-to-end throughput | 86k to 154k / 64k to 100k packets/s | *measured*, varies run to run (see #4) |
| Docker: nginx during API startup | **502** seen at t+8 s after `docker compose up`; first healthy response about 70 s after `up` on this machine (the API app itself reports startup in about 12 s) | *measured*; confirms #8 |
| Docker: cold image build | about 7 min (corpus regeneration and model training run at build time) | *measured* |
| Analysis of `demo_gateway_audit` through the API, after #15 | **1.35 s → 0.13 s** (median of 6, warm server) | *measured* |
| 3,461-tunnel stress capture (544k packets), full analysis, after #15 and #16 | **316 s → 11 s** (reconstruction alone 8.5 s → 1.3 s) | *measured* |
| `python -m ipsec_analyzer.evaluation`, after #12 and #15 | **47 s → 9 s**, same `EVAL.json` apart from the run-dependent fields | *measured* |

---

## Tier 0: cannot affect runtime behaviour: DONE

| # | Optimization | Status | What was done and how it was verified |
|---|---|---|---|
| 1 | **Pin Python dependencies** | Done | `backend/constraints.txt` pins all 54 packages to the tested versions; the README installs with `-r requirements.txt -c constraints.txt`. `engines: node >=20` added to `package.json`. `backend/Dockerfile` installs with the same constraints (verified in Docker, see #6). |
| 2 | **README fixes** | Done | Prerequisites (Python 3.11 with a working `venv`/`ensurepip`, `uv venv --seed` fallback, Node 20+, ports 8000/5173 free), `npm ci`, the esbuild warning, and the new commands. |
| 3 | **Untrack `data/_lab_run.log`** | Done | `git rm --cached` plus a `.gitignore` entry; the file is still on disk. |
| 4 | **Run-dependent fields in `docs/EVAL.json`** | Done (documented) | The Evaluation page displays `generated_at` and `throughput`, so they stay in the file. The README now explains this and gives a one-line check that compares everything else (run as documented: `metrics identical: True`). |
| 5 | **Commit the browser smoke tests** | Done | `frontend/e2e/smoke.mjs`, run with `npm run e2e`. No dependencies (Node 22+ and a local Chrome/Chromium/Edge). 35 checks across navigation, upload, a bundled scenario, results, tunnel detail, downloads, and the Evaluation page against `/api/metrics`. A mutation check showed it fails when expectations are broken, and it deletes the analyses it creates. |
| 6 | **Docker: lockfile, `npm ci` and pinned backend install** | Done and verified in Docker | `frontend/Dockerfile` copies `package-lock.json` and runs `npm ci`; `backend/Dockerfile` installs with `-c constraints.txt`. `docker compose build` succeeds (about 7 min cold; web image 74 MB, API image 1.32 GB). The full stack (nginx, API, Postgres) passes all 35 browser smoke checks at http://localhost:8080, and the pinned API image passes all 14 backend tests inside the container (Linux, Python 3.11.17). |

## Tier 1: low risk, easy to verify

| # | Optimization | Benefit | Risk | How to de-risk |
|---|---|---|---|---|
| 7 | **Warm up the anomaly model and SHAP at API startup** | Removes the ~3.5 s first-click penalty (5.5 s vs ~1.5 to 2 s, *measured*) | Low: slower API start; results unchanged | Compare the first analysis time before/after, and per-tunnel scores. |
| 8 | **Compose: API healthcheck and `depends_on: condition: service_healthy` for `web`** | Avoids the 502 nginx returns while the API starts (*measured*: seen at t+8 s; `depends_on` currently only waits for the container to start) | Low (Docker only) | `docker compose up` from cold and load the page immediately. |
| 9 | **nginx: gzip, long cache for hashed `/assets` and `/fonts`, no-cache for `index.html`** | Faster repeat loads, smaller transfer | Low (Docker only) | Check headers with `curl -I`; confirm a hard refresh still picks up a new build. |
| 10 | **Delete unused code** | Smaller surface to maintain | Very low | **Done:** unused parser constants, imports and CSS rules, and `pandas` from `requirements.txt` (only `shap` needs it, and pulls it in itself). Tunnel and stats fields stay: they reach the API payload and the JSON export. Tests pass and the corpus is byte-identical. |
| 11 | **Cache the `/api/samples` manifests** (reload when the file's modification time changes) | Three JSON files no longer re-read on every request | Very low | **Not done:** measured at 1.5 ms per request, so a cache would add code for no visible gain. |
| 12 | **Reuse parses in `evaluation.validate_public`** (each IKEv1 capture is parsed twice) and **analyse keyless captures once** in the evaluation run | Faster evaluation | None to the demo (offline script) | **Done**, and the evaluation now scores all captures' tunnels in one batch (see #15). Same `docs/EVAL.json`. |
| 13 | **Move Postgres credentials to environment or secrets** in `docker-compose.yml` | Better hygiene | Low | `docker compose up` still works. |
| 14 | **Upload housekeeping**: clear old files in `data/uploads/` | Stops disk growth over many uploads | Low | *Unverified:* whether files accumulate; check before changing. |

## Tier 2: medium risk (only with before/after proof)

| # | Optimization | Benefit | Risk | How to de-risk |
|---|---|---|---|---|
| 15 | **Batch anomaly scoring across tunnels** | Largest speed-up on analyze (*measured*, see above) | Medium: touches scoring and SHAP | **Done:** one `IsolationForest` call per group for all tunnels (each call cost ~35 ms of fixed overhead), and a SHAP explainer that cannot be built for a single-feature forest is no longer rebuilt for every tunnel. Per-tunnel payloads for `demo_gateway_audit` and the stress capture, the trained model file and `EVAL.json` are identical before and after. |
| 16 | **Index the lookups in `sa/reconstruct.py`** | Matters for large captures | Medium: core reconstruction | **Done:** `prior_attempts` and ESP-to-tunnel matching use dictionaries, half-open counting narrows its window with `bisect`. Identical results as #15. |
| 17 | **Tighten CORS** (`allow_origins=["*"]` today) | Hardening | Medium: could block a demo served from another origin | Make it an environment setting, defaulting to the current behaviour. |
| 18 | **Name the magic numbers in `synth/simulate.py`** (about 60 raw values) | Readability only | Low-medium: a large generator diff | Byte-identical corpus. |
| 19 | **Run the backend container as a non-root user**, and slim the image | Hygiene, smaller image | Medium (Docker only) | Full `docker compose build` and `up`. |

## Tier 3: do not touch before the demo

| # | Optimization | Why not |
|---|---|---|
| 20 | **Collapse repeated rule IDs in the backend** (for example `ESP-SEQ-REPLAY` ×3 on one tunnel) | Changes violation counts, PDF content and probably metrics, so the numbers on screen shift. The UI already groups them visually. |
| 21 | **Store list-view fields in database columns** instead of re-reading each tunnel's JSON in `list_tunnels` and `remediation` | Schema change; existing `analyzer.db` rows would break. Negligible gain at 12 tunnels. |
| 22 | **Merge `_parse_v2` into `_walk`** in `parser/ike.py` | Parser core; maintainability only, no demo benefit. |
| 23 | **Make `create_analysis` a plain `def`** instead of `async` with blocking I/O | Behaviour change under concurrency; no benefit for a single-user demo. |
| 24 | **Act on `has_hash`** (it is now set correctly but nothing reads it) | A new rule would change findings and risk scores. Do it after the demo, with new tests. |

## Verification gaps (not optimizations, but worth closing)

- The UI has only been looked at in **light mode**; dark mode follows the OS setting and is unverified.
- Only **Python 3.11** has been tested; the README says 3.14 lacks wheels for some dependencies.

## Suggested order

1. ~~Tier 0 (#1 to #6)~~ done, including the Docker verification.
2. **Next (Tier 1):** #7 first, since it has the largest visible effect, then #8 and #9 if the demo runs through Docker.
3. ~~**Only with proof (Tier 2):** #15~~ done with proof, together with #16.
4. **After the demo:** all of Tier 3.
