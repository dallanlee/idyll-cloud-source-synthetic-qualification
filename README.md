# Synthetic source qualification

This public repository contains a sanitized, bounded qualification package.
It has fresh Git history, synthetic placeholders, and no personal source records.

The source runner is disabled in code (`SOURCE_CONFIGURED = False`). Its workflow
remains in `drafts/`, outside GitHub Actions' active workflow directory. Importing
the modules does not load credentials or access a provider. Local tests model
provider responses; passing them does not qualify live source execution.

Run local checks with:

```sh
python3 -B -m unittest discover -s tests -v
```

The separately reviewed GitHub control probe uses only this synthetic repository.
It creates one retained synthetic claim per Actions run, checks the provider's
annotation response, and attempts forbidden changes to the claim, stop tag, and
protected code branch. It uses a native, ephemeral job token with repository-wide
`contents: write`; it has no ClickUp token and does not call ClickUp. It is manual,
finite, and has no schedule or automatic retry.

`qualification-source` requires the designated owner's review, prevents
self-review, prohibits administrator bypass, and permits deployment only from
`codex/qualification`. The native reviewer/dispatcher identity arrangement is
still unqualified. Code/stop protection has an administrator bypass; claim
update/delete protection has none. Administrators can still edit repository
settings: this setup does not claim to constrain the account owner.

Before a live source test: provision a dedicated synthetic-only ClickUp Workspace,
read back its fixture and OAuth authority, replace the inert placeholders, review
the exact final code, prove the environment and tag controls with the actual job
principal, approve one finite occurrence, and qualify cancellation and independent
executor cessation. Source access, source grant, and production acceptance are
separate gates. Unknown effects never authorize automatic replay.

`scripts/prepare_clickup_oauth.py` is a loopback-only authorization landing
preparation, not a connected source. It binds `127.0.0.1:8768`, uses an expiring
one-use state, and keeps a returned authorization code only in memory. It has no
token exchange, secret export, GitHub upload, or source operation. Selection of
the sole synthetic Workspace must be independently verified by a separately
reviewed token consumer before the connection or source scope is accepted.
Create the OAuth app only after its own approval; keep the landing inactive
until the actual authorization and subsequent consumer are ready.
## Synthetic OAuth connection and inert environment test

The dedicated app must authorize only **Idyll Cloud Qualification — Synthetic Only**.
`connect_clickup_oauth.py` is a one-use consumer. It exchanges the code with the
fixed ClickUp HTTPS token endpoint, verifies the sole authorized Workspace through
the fixed Workspace endpoint, then uploads only to `qualification-source` as
`QUAL_CLICKUP_OAUTH_TOKEN` through `gh` stdin. It has no task read or workflow dispatch.
It checks the protected storage route before credential entry, before exchange,
and again before upload. Credentials have no command-line, environment-variable,
log or file input. A human supplies the new app secret through hidden terminal input.

The gate requires exact clean local/remote code, unchanged reviewer/branch controls,
zero existing environment secrets, native distinct-actor approval and a live
self-review-negative case. The two new **manual-only, credential-free** workflows
test that route with an ephemeral Actions token. The temporary dispatcher has
`actions: write`, which is broader underlying authority than its fixed dispatch
operation. This is a machine dispatcher plus Dallan's human review; two-human
independence is not established. Actor identity and approval feasibility are
unqualified until actual GitHub readbacks. Probe run numbers/attempts, finite
authority variables and exact head restrict the planned sequence. Retire both
workflows before credential entry, and cancel the retained negative case afterward.
No approval policy is weakened by this package.

Do not start the consumer until exact independent code review, native gate proof
and the human's source-grant action are ready. DNS duration is not bounded by the
HTTP socket timeout. Browser-history erasure and secure memory zeroization are
not claimed. Overbroad grants are refused and discarded locally; the owner must
revoke them in ClickUp because dropping a reference does not revoke provider access.
An uncertain exchange/upload blocks automatic replay. Secret metadata confirms
the name, not the stored credential value. The source runner remains disabled.
