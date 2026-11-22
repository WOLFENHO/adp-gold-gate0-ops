# ADP Gold Gate 0 operations

This repository is intended to be **private**, with `main` as its default branch. It contains only two manually triggered workflows. It is separate from the ADP application repository, so publishing it does not trigger a Production Vercel build.

## Backup and isolated restore

The `ADP Rehearsal Gate 0 backup and restore` workflow requires a repository Actions secret named `SUPABASE_DB_URL`. Put only ADP-Rehearsal's **session-pooler** Postgres connection URL in that secret. The runner validates its database name, port, pooler hostname, SSL setting and project-specific user. It checks Release 121, captures the source timestamp and identity, exports roles/schema/data, checks Auth and Storage metadata are included, compares schema and table fingerprints after an isolated local restore, and checks the archive's SHA-256 integrity. It emits fixed results only.

The successful run stores a private GitHub Actions artifact named `adp-rehearsal-gate0-verified` for seven days. It contains a manifest and plaintext SQL for recovery; limit repository access to authorized operators. The artifact is unavailable from a public repository because this package must only be installed in a private one. The disposable local database and transient plaintext files are removed from the runner. GitHub's hosted runner is discarded afterward.

The SQL export excludes `storage.buckets_vectors` and `storage.vector_indexes` per Supabase's restore guidance. Storage **object bytes**, external provider settings, OAuth settings, Mux assets and secrets are outside this logical database backup. The artifact is a verified database recovery input, not a complete clone of every platform service.

On GitHub Free, private repositories cannot use environment secrets. A private repository Actions secret is the compatible fallback. On GitHub Pro or above, the secret can be moved into an `adp-rehearsal-gate0` environment and the job can be bound to that environment.

No workflow is scheduled. Both use `workflow_dispatch`, `contents: read`, fixed branch/project checks, job timeouts and non-cancelling concurrency groups.

## Protected runtime check

The separate `ADP Rehearsal protected runtime check` workflow is prepared but requires repository secrets `VERCEL_TOKEN` and `ADP_GOLD_RUNTIME_TOKEN`, plus an exact immutable Preview URL as its manual input. It uses `vercel curl` to provide Vercel's protection bypass and the endpoint's custom header, invokes the existing read-only route once, and records only the route's fixed code.

The current Preview was built with the runtime token absent and the expiry disabled. Environment changes cannot alter its immutable runtime. Therefore this workflow **cannot** establish credential acceptance on that deployment. A later protected Preview built with a matching token and bounded expiry, or a separately reviewed route change, is required before running the workflow for Gate 0. This package does not deploy anything or change Vercel environment variables.
