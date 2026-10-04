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

The original inert review window expired without human approval; its waiting
cases are retired and preserved. The fresh intent permits only probe runs 5/6
and dispatcher run 3, all attempt 1. Its human review window is two hours;
execution still has a one-minute job limit and zero source operations. Prepare
the owner handoff before starting that clock. The source-read window and the
one-use OAuth handler lifetime are unchanged.

Do not start the consumer until exact independent code review, native gate proof
and the human's source-grant action are ready. DNS duration is not bounded by the
HTTP socket timeout. Browser-history erasure and secure memory zeroization are
not claimed. Overbroad grants are refused and discarded locally; the owner must
revoke them in ClickUp because dropping a reference does not revoke provider access.
An uncertain exchange/upload blocks automatic replay. Secret metadata confirms
the name, not the stored credential value. The source runner remains disabled.

The loopback start page uses `Referrer-Policy: same-origin` so a browser form
POST carries the exact loopback Origin required by the handler. Cross-origin
referrers remain suppressed. Redirect, callback, result and error responses
retain `no-referrer`; null, missing and foreign Origins remain refused. The
original no-referrer start page was verified to send Origin: null in a real
browser. Credential-free browser validation supplements the offline tests.

## Inactive fixed observation and fresh retained-stop case

`source_observation.py` is a separate reader with `OBSERVATION_CONFIGURED = False`.
It compiles the sole fabricated Task `86bccact7`, Workspace `90141728025`, List
`901421854627` and exact synthetic description. It never lists/discovers source
objects or uses the existing consumer. HTTP200, exact identities/content and a
canonical decimal string `date_updated` are required. The revision is captured
from the raw response; a guessed timestamp is never used. Evidence contains only
these identities/revision, description equality/hash, occurrence/run attribution,
operation counts and times. Response bodies, descriptions, headers and error text
are never printed. The original `SOURCE_CONFIGURED = False` remains unchanged.

The new observation, retained-stop and dispatcher workflows are all in `drafts/`.
`STOP_PROBE_CONFIGURED` and `DISPATCH_CONFIGURED` also default to literal False.
Imports and inactive entrypoints do not consume credentials or contact providers.
The new dispatcher has its own fresh native run-number intent; none of the old
consumed control or approval cases is reused.

For an independently reviewed **source-free activation variant**, change only
`STOP_PROBE_CONFIGURED = False` to `True` in `retained_stop_probe.py` and
`DISPATCH_CONFIGURED = False` to `True` in `finite_case_dispatcher.py`, and move
`drafts/retained-stop-qualification.yml` and
`drafts/qualification-case-dispatcher.yml` to `.github/workflows/`. Update the
publication manifest for those two moves. Commit/review that exact final variant;
the accepted SHA must be its resulting code SHA. Keep the observer literal False,
its workflow in drafts, and the original source/consumer unchanged. Publication
does not authorize execution: leave the new workflows disabled and finite
authority absent until the named case is ready.

The stop case requires the owner-created fixed lightweight stop ref to point at
that accepted SHA. Its reviewed valid alternate is the existing distinct commit
`260d783935a0f47eed9222ec66f48e7502cb30b7`. The job verifies the exact repository,
branch, environment/reviewer/branch policy, native bot run/attempt, actual human
approval, active stop and claim rulesets, existing alternate and stop identity.
It acquires and reads back a retained annotated occurrence before attempting at
most one fixed PATCH (`force: true`, avoiding a fast-forward validation ambiguity)
and one DELETE. Only an attributable ruleset refusal plus exact retained readback
can pass. A generic422, wrong/changed/absent stop, lost response or duplicate claim
fails closed. Unexpected PATCH success stops before DELETE. No source credential
is accepted by the stop or dispatcher modes.

Protected stop authority variables are `QUAL_STOP_ACCEPTED_CODE_SHA`,
`QUAL_STOP_APPROVED_RUN_ID`, `QUAL_STOP_APPROVED_OCCURRENCE_ID`, `QUAL_STOP_DUE_AT`,
`QUAL_STOP_CUTOFF_AT`, and `QUAL_STOP_APPROVED=idyll-cloud-q-v1-retained-stop`.
The manual input is only the exact occurrence. Bind the new bot run ID after
dispatch and before its owner approval. `qualification-source` supplies the
existing native review gate; this source-free workflow references no source
secret. One explicit due/cutoff window of at most120 seconds must remain valid at
entry and after every provider call. An approval after cutoff performs no call.

Fresh dispatcher variables are `QUAL_DISPATCH_ACCEPTED_CODE_SHA`,
`QUAL_DISPATCH_APPROVED_RUN_NUMBER`, `QUAL_DISPATCH_APPROVED_OCCURRENCE_ID`,
`QUAL_DISPATCH_DUE_AT`, `QUAL_DISPATCH_CUTOFF_AT`,
`QUAL_DISPATCH_APPROVED=idyll-cloud-q-v1-case-dispatcher` and
`QUAL_DISPATCH_CASE=retained-stop`. The human starts its one approved new native
run number/attempt1; the ephemeral Actions token makes one fixed workflow dispatch
so the bot is distinct from the designated human reviewer. Its underlying
`actions: write` authority is repository-wide; code binds one target/occurrence.
Observation is a separately approved future target; its literal/workflow remain
inactive throughout stop qualification. Missing native actor/metadata rights is
a blocker, never a reason to use a personal token or weaken protection.
GitHub documents `actions: read` for both
[environment metadata](https://docs.github.com/en/rest/deployments/environments#get-an-environment)
and [deployment branch-policy listing](https://docs.github.com/en/rest/deployments/branch-policies#list-deployment-branch-policies),
including installation tokens and unauthenticated public reads. The new protected
jobs request that permission; actual job-principal access still needs readback.

Retire each finite case by disabling both newly published workflows, removing its
finite authority variables, cancelling any still-waiting run, and verifying native
run/attempt and independent executor cessation. A queued/waiting job is not proof
of executor termination. Expiry consumes authority and never authorizes an
automatic retry. Retain the stop/occurrence refs as evidence; owner retirement of
the stop before a later source observation needs its own explicit action.

The future observation uses the corresponding six `QUAL_OBSERVATION_` variables,
with `APPROVED=idyll-cloud-q-v1-observation`, and the sole protected OAuth secret.
It requires a new exact code review/activation, native protected approval, a fresh
window/run/occurrence, absent retained stop, and all retained-stop evidence first.
This preparation does not approve that source-enabling change or dispatch.

`run_source_observation.py` removes injected credentials from its environment and
hands them to a fresh isolated Linux child through capped, nonblocking stdin.
`bounded_executor.py` independently covers all child work, including cold DNS,
TLS, connection and body reads, using wall and monotonic deadlines. It validates
capped positive-allowlist result frames, kills the entire child process group and
reaps the local executor on success, failure, interruption and timeout. The Linux
child installs a parent-death SIGKILL guard before reading credentials. A partial
receipt preserves unknown effects and never claims a zero provider count without
evidence. GitHub attempts/actions are counted separately from the single source
attempt/action. This proves a local mechanism; actual hosted approvals, metadata
permissions, cancellation, rule refusals and independently correlated provider
executor cessation remain live qualification gates.

Offline tests exercise a real child blocked inside the HTTPS DNS path using a
native stalled resolver with no outbound traffic, plus a child that never reads
stdin, untrusted/oversized IPC, success followed by a sleeping child, exact source
validation, finite/native admission, stop arrival, immutable claim reconciliation,
and rule-refusal/readback semantics. Linux `prctl` and hosted Actions behavior are
not established by the macOS subprocess tests. No test loads real credentials,
uses an existing CLI session, calls a provider, dispatches or starts a service.
