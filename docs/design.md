# Hedgehog — Initial Design (Draft v2)

Status: draft for discussion · 2026-11-22

## 1. Goal and principles

Hedgehog is an **in-cluster, fully automatic, immediate-mitigation** controller for critical, actively exploited
vulnerabilities in running container images. It:

1. Keeps a list of every image running in the cluster (by digest).
2. Scans each image with grype, and re-checks when the vulnerability DB changes.
3. Builds a patched image for each in-scope finding: copa for package-manager content, and Hedgehog's own **runtime
   replacement** for what no package manager tracks (currently `node`). It pushes to a separate registry and moves
   running workloads onto it.
4. Hard-denies changes that would introduce or keep an in-scope vulnerable image. Hedgehog is a stop-gap; the owning
   team's next change must fix the issue properly.

Principles:
- **No extra moving parts.** Only `DESTINATION` is required (plus push credentials `DESTINATION_USERNAME`,
  `DESTINATION_PASSWORD` from a Secret in the manifest). Every value the design names below is an environment
  variable defaulting to that value; there are no CRDs or config files. The full list is in the header of
  `deploy/hedgehog.yaml`.
- **No access to workload secrets.** Source images are pulled anonymously and nodes pull patched images without a pull
  secret. Hedgehog reads no Secrets; credentials it needs are passed in as environment variables.
- **Reactive.** When nothing is being mitigated, Hedgehog stays out of the admission path apart from a cache lookup.
- **Never change workload specs.** Images are rewritten on Pods as they're created. The only write to a workload is the
  standard restart annotation that triggers its native rollout (§7.2).
- **Own your state.** State lives in Hedgehog's own database on a persistent volume. No CRDs, no ConfigMaps used as
  storage, no Events.
- **Narrow scope.** Current `node:22`, `node:22-alpine` and `python:3.12` (2,500+ findings each) have **zero** in-scope findings.
- **Registry-agnostic** (any OCI registry). **No speculative abstraction:** node is replaced by concrete code; a
  shared interface comes when a second runtime does.

Target: one installation per cluster, low hundreds of distinct images.

## 2. Scope filter (fixed)

A finding is actionable when `vulnerability.risk > 90` **and** `vulnerability.fix.state == "fixed"` (grype 0.122.1 JSON).

`risk = min(threat × severity × kevMod, 1) × 100` (Appendix A). In practice `risk > 90` means:
- **On the KEV list** with severity factor > 0.857 (> 0.818 with known ransomware use). That covers a Critical label with
  average CVSS ≥ 8.2, a Critical label with no CVSS (94.5), or a High label with CVSS ≥ 9.7.
- **Not on KEV:** only if EPSS > 0.9 together with near-maximum severity. That's very rare.

Grype is pinned. A unit test recomputes `risk` from the JSON fields, so formula changes are caught on upgrade.

Target version = the **nearest fixed version above the installed one**, even across major versions (node 16.20.2 → 22.23.4).

Observed in `node:16-alpine`:

| CVE | Package | Type | EPSS | KEV | Risk | Actionable |
|---|---|---|---|---|---|---|
| CVE-2026-111497 | node 16.20.2 `/usr/local/bin/node` | binary | 0.999 | yes | 97.1 | **yes**, via node replacement |
| CVE-2024-5535 | libssl3 3.1.2-r0 | apk | 0.061 | no | 5.6 | no |
| GHSA-23hp-3jrh-7fpw | tar 6.1.11 (npm-bundled) | npm | 0.006 | no | 0.5 | no |

Out of scope: rebuilding static application binaries (Go/Rust apps).

## 3. Components

```
 ┌──────────────────────────── hedgehog-system ─────────────────────────────┐
 │                                                                          │
 │  hedgehog  (one binary, one process; StatefulSet, 1 replica, PV)         │
 │   + buildkitd sidecar (rootless, loopback only; same node, so native)    │
 │   ├─ inventory   watch Pods → digests, owners, tag → digest              │
 │   ├─ scanner     exec syft/grype; SBOMs + grype DB on the PV             │
 │   ├─ patcher     copa generate + node replacement → one layer → push     │
 │   ├─ rollout     restart annotation; the native rollout does the rest    │
 │   ├─ webhooks    :8443 mutating (rewrite) + validating (deny/scan)       │
 │   ├─ http        :8080 /status /metrics /healthz                         │
 │   └─ bbolt DB    on the PV                                               │
 └──────────────────────────────────────────────────────────────────────────┘
```

Stack: Go, controller-runtime as a library (manager, shared cache, webhook server, metrics, health probes; no CRDs,
no Kubebuilder scaffolding), cert-controller, go-containerregistry, `go.etcd.io/bbolt`, and pinned grype/syft/copa
binaries in the image. The code is `cmd/hedgehog` (entry point) plus one flat `internal` package. The e2e test (`e2e/`, run
with Tilt on a k3d cluster with an in-cluster registry; see the `Tiltfile`) deploys a Node2Shell-vulnerable
`node:22.23.3-alpine`. It checks the patch, the restart, the rewritten Pods and both deny paths.

**One process.** bbolt and the RWO volume already limit Hedgehog to one replica, so the webhooks run in the same
process and read the same in-memory snapshot. A rewrite is live for admission the moment it's stored: there's no state
stream between components, no replica acknowledgements, and no separate webhook deployment. Both webhooks fail open
(§7.4).

**TLS** comes from cert-controller (Open Policy Agent, as used by Gatekeeper), running in-process: it creates and
rotates the serving cert in the `hedgehog-webhook-tls` Secret (mounted at `/certs`) and injects the CA into both
webhook configurations.

## 4. State

Everything lives on the controller's PV:

```
/data/hedgehog.db        bbolt
/data/sbom/<digest>.json syft-json SBOMs
/data/grype-db/          grype vulnerability DB
```

One bbolt bucket, `images`. The key is the source digest, and the value is a JSON record:

```go
type ImageRecord struct {
    Source     string    `json:"source"`     // repo@sha256:..., where to pull the image from
    DBBuilt    string    `json:"dbBuilt"`    // grype DB build the findings came from
    Findings   []Finding `json:"findings"`   // actionable findings only; empty = clean
    Patched    string    `json:"patched"`    // patched digest; non-empty = active rewrite
    PatchedFor []string  `json:"patchedFor"` // vulnerability IDs the patch covers; new findings trigger a re-patch (§6.3)
    PatchError string    `json:"patchError"` // last patch failure (e.g. EOL distro); retried once per new grype DB
}
```

There are no queries to run: each read and update is one bbolt transaction (low hundreds of small records). bbolt provides crash-safe transactions in a single file. It locks the file to one
process, which matches the single controller replica.

Everything else is kept in memory and rebuilt from the cluster when the controller starts: which workloads use which
digest and tag → digest (both from the Pod informer), and the idle/active mode (computed). The SBOM files sit next to
the DB. The only field that really matters is `Patched`; everything else can be rebuilt by re-scanning. If the PV is
lost, images are re-scanned and re-patched.

**Garbage collection, by reference count.** An image's references are the running Pods using it (as their source or as
their running digest) and, for a patched image, its source's record while that source is referenced. Once an image has
had no references for 7 days, its record and SBOM are deleted. This only covers Hedgehog's own state: registries are
never touched, and pushed images are the registry owner's to clean up. The grace period covers workloads that only run sometimes
(CronJobs, scaled to zero), which would otherwise lose their patch between runs. The unreferenced-since times are kept
in memory, so a Hedgehog restart only delays collection.

## 5. Scanning

- **Inventory:** watch Pods and read the `imageID` of init and regular container statuses (covers every workload kind). Walk ownerRefs to the top-level workload. Images are pulled anonymously; workloads'
  `imagePullSecrets` are never read.
- **New digest:** syft SBOM → saved on the PV → `grype sbom:` → store actionable findings in the image record.
- **DB update:** poll every 15 min. When a new grype DB is out, re-match every saved SBOM; no image pulls.
- **Priority:** inline admission scans > new digests > re-matches.
- **Failures back off:** a background scan that fails (an image that can't be pulled anonymously, or isn't built for
  Hedgehog's platform) is retried after 1, 2, 4, … minutes, at most hourly. The backoff is kept in memory. Inline
  admission scans don't wait for it.

Measured on a workstation (16 cores, fast network; in-cluster will be slower):

| Operation | Time |
|---|---|
| Full scan, busybox (floor, mostly DB load) | 1.4 s |
| Full scan, alpine-based node | ~4 s |
| Full scan, node:22 / python:3.12 (Debian, ~400 MB) | 14.5–17 s |
| Re-match saved SBOM | ~2–9 s |

## 6. Patching

### 6.1 copa (`copa generate`)

Convert actionable grype matches to a **copa v1alpha2** report: `osupdates` for apk/deb/rpm, and, only with
`PATCH_DEPENDENCIES=true`, `langupdates` for application dependencies (npm/pip/etc.) (copa's experimental support: `COPA_EXPERIMENTAL=1`,
`--pkg-types os,library`). With it off, dependency findings are unpatchable. Mapping: `artifact.name` → `name`, `artifact.version` → `installedVersion`,
target → `fixedVersion`, `vulnerability.id` → `vulnerabilityID`; `metadata.os` comes from grype `distro`. Then run:
`copa generate --scanner native -r report.json -i <src@digest> --addr tcp://127.0.0.1:1234 --output-context ctx.tar`.
Skip this step if there are no OS or dependency updates.

`copa generate` runs the package manager in BuildKit and outputs a build context: a Dockerfile
(`FROM <src>` / `COPY patch/ /`) and the changed files under `patch/`. Hedgehog **doesn't build that Dockerfile**:
- It copies the `patch/` entries (with the prefix stripped) into its own layer tar. copa writes the diff's whiteout
  files (`.wh.*`) as ordinary entries; with the prefix stripped they're layer whiteouts again, so files the package
  manager deleted stay deleted. A `COPY patch/ /` build would not preserve them.
- The node replacement writes its files into **the same layer**, after copa's entries, so it wins on any path both touch.
- Hedgehog appends that one layer to the source image (go-containerregistry), edits the config (`NODE_VERSION`, an
  `io.hedgehog.source` label), and pushes to `<dest>/<source repo>:sha256-<source hex>`.

So: one build in BuildKit (copa's), one layer, one push. No Dockerfile build and no `buildctl`.

A patch fails, and the image is unpatchable, for example when copa fails (e.g. an EOL distro's repos are gone), a
finding has no fix version above the installed one, a package type neither copa nor node replacement covers, or a patched image that still has a finding
the patch was for (§6.3).

### 6.2 Node runtime replacement

Node isn't tracked by a package manager in the official images, so copa can't update it. Findings in the node
binary or its bundled npm/corepack are fixed by replacing the runtime, in two steps: plan before anything is built
(so unpatchable images fail fast), then write the files after copa's entries. It's concrete code called directly by
the patch step; there's no handler interface until a second runtime needs one.

- **Detect:** grype is the source of truth. The node binary is replaced at the path grype reports for it, wherever
  that is. The bundled npm or corepack directory is replaced where grype reports findings inside it. No install layout
  (`<prefix>/bin`, headers, symlinks) is assumed. libc comes from `distro`, arch from Hedgehog's platform.
- **Target:** the nearest fixed version above the installed one, from grype `fix.versions` (ignore entries below the
  installed version; grype lists `11.0.0` for CVE-2026-111497). Use the latest patch release of that line from the Node
  `index.json`.
- **Fetch:** `nodejs.org/dist` (glibc) or `unofficial-builds.nodejs.org` (musl). Verify the tarball's SHA-256 against
  `SHASUMS256.txt` fetched over TLS, the same trust level as the grype, syft and copa downloads. There is no GPG check:
  TLS covers transit, and unofficial-builds (musl) isn't signed anyway.
- **Layer:** the release's `bin/node` at the binary's path; its `lib/node_modules/{npm,corepack}` over the
  directories grype found (opaque whiteout, so old files can't linger; deleted if the release doesn't ship it). Update
  `ENV NODE_VERSION`.
- **Risk:** native addons (`*.node`) won't load after a major version bump. The native rollout
  stalls on unready Pods (§7.2).

### 6.3 Publish and check

1. The patched image is pushed and rolled out without a separate verification step. copa itself fails the build if
   any OS package ends up below its fixed version, and the node release is chosen at or above grype's fix and
   checksum-verified. Once live, the patched digest is scanned like any other image (it gets its own record). If it
   still has a finding the patch was for, the patch didn't work: `Patched` is cleared and `Error` set, so the image is
   treated as unpatchable (no rewrite, denied, retried once per new DB). Findings the patch wasn't for are new CVEs:
   the source has them too and gets re-patched. A patched digest counts as clean until its own scan says otherwise.
   There is no runtime check: a patch that breaks the app shows up as the native rollout stalling (§7.2).
2. One platform: the one Hedgehog runs on. copa runs the package manager inside the target image on buildkitd, and
   rootless buildkitd can't emulate other architectures, so builds are native. buildkitd is a sidecar in Hedgehog's Pod,
   so it's always on Hedgehog's node and architecture. Multi-arch indexes are future work.
3. **No image signing.** Pods are rewritten to `repo@sha256:…`, so they run exactly the content Hedgehog verified, and
   a tampered registry copy would have a different digest. The cluster doesn't enforce signatures. If one ever does,
   Hedgehog's destination repository must be exempted from that policy.
4. Always patch from the original digest. When there are new findings, re-patch from the original, push to the same
   tag, and update `Patched`.

## 7. Admission and rollout

### 7.1 Cluster-wide modes

The cluster is in one of two modes, decided by the controller and streamed to the webhooks:

- **Idle:** no image record with `Patched` set, and no unpatchable actionable image in use. This is the normal state.
- **Active:** at least one rewrite, or an actionable image in use that can't be patched. This is an ongoing mitigation.

| Request | Idle | Active |
|---|---|---|
| Workload CREATE, or UPDATE that changes `spec.template` | Images known actionable → **deny**. Otherwise **allow**; unknown digests are queued for a background scan | Every image must be **known clean**. Unknown → **inline scan** (20 s budget): clean → allow, actionable → deny, over budget → deny "scanning, retry". Known actionable → deny |
| Workload UPDATE without a template change (metadata, labels, Argo tracking), or only `restartedAt` | Allow | Allow |
| Pod CREATE (mutating) | No-op | Image record has a `Patched` digest → rewrite to the patched digest, annotate `hedgehog.io/source-images` |
| Pod CREATE (validating) | Known actionable → deny | Same rules as workloads (owned Pods are almost always known by now; this covers moved tags and kinds the workload gate doesn't see) |
| Scale subresource | Not intercepted | Not intercepted |

"Known actionable" is a lookup in the in-memory snapshot, never a scan. Workload kinds come from a fixed, built-in list
(Deployment, StatefulSet, DaemonSet, ReplicaSet, Job, CronJob, Argo `Rollout`); anything else is caught at the Pod level.

**What idle mode gives up:** a never-seen vulnerable image is admitted. It's caught by the background scan, patched and
rewritten. The exposure window is scan + build + rollout, typically minutes. Detection switches the cluster to active mode,
and from then on every change is verified inline until the mitigation ends.

**Active mode ends** when no workload uses a rewritten or unpatchable actionable image any more, i.e. the teams have
shipped fixed images.

### 7.2 Rollout: native restart (constants, no settings)

Hedgehog does exactly what `kubectl rollout restart` does: it sets the restart annotation, and nothing more. The
workload's own controller replaces Pods according to its own strategy, and the mutating webhook rewrites each new Pod
to the patched digest. The image in the workload spec never changes. Hedgehog has no restart logic of its own.

**The only write to a workload:** `spec.template.metadata.annotations["kubectl.kubernetes.io/restartedAt"]`, applied
with a server-side apply patch under field manager `hedgehog`, so Hedgehog owns only that field. The validating
webhook allows updates that only change this annotation.

**Sequence per source digest:**
1. Patch pushed → set `Patched` on the image record. The in-process snapshot is rebuilt at once, so new Pods are
   rewritten from here on. Nodes pull the patched image without a pull secret: the destination must be public or
   covered by node-level registry credentials.
2. The reconcile loop sets the annotation on each Deployment, StatefulSet and DaemonSet that still runs the source
   digest. Hedgehog doesn't wait or watch: progress is visible in each workload's own status, and `/status` lists the
   workloads not yet on the current patch.

**Continuous:** every reconcile checks every patched image's workloads, so a missed Pod is caught whenever it shows
up, not only right after the patch. The workload's own `restartedAt` is the record: a workload is restarted when a Pod
running the source digest, or an earlier patch of it, was created after its last restart. Then either it hasn't been
restarted since the current patch (a first patch, or a re-patch for new findings), or the webhook missed that Pod
(Hedgehog was down). Pods older than the last restart belong to a rollout in progress or
stalled, which another restart wouldn't help, so a stalled rollout isn't restarted over and over. Clock skew between
Hedgehog (which writes `restartedAt`) and the API server (which sets `creationTimestamp`) can cause at most one extra
restart.

**By workload kind:**

| Kind | Annotation set? | What happens |
|---|---|---|
| Deployment, StatefulSet, DaemonSet | **Yes** | Whatever the workload's strategy does (rolling update, `Recreate`, StatefulSet `partition`) |
| ...with `updateStrategy: OnDelete` | Yes (it's harmless) | Nothing; `OnDelete` replaces Pods only when they're deleted. Ignored |
| Argo `Rollout`, Job, CronJob, bare Pod, anything else | No (`kubectl rollout restart` doesn't support them) | Ignored |

"Ignored" only applies to rollout. Admission still covers these kinds, and their Pods are still rewritten whenever they're
created for their own reasons (scale-up, node drain, crash, the team's own rollout, the next Job run). Ignored workloads
not yet on the current patch are listed in `/status` with the rest.

PDBs don't apply: they only limit evictions, and rolling updates don't use evictions.

**Fail closed:** a broken patch shows up as the rollout stalling: patched Pods never become Ready, and the Deployment
eventually reports `ProgressDeadlineExceeded` (default 600 s). The rewrite stays, the workload shows in
`/status` as not yet on the current patch, and the vulnerable image is never reintroduced. The workload controller does keep the old Pods it hasn't
replaced yet running, still vulnerable, until the team ships a fix.

**Patch not ready yet:** Pods are denied while their patch builds. Once it's ready, the restart takes over.

**Argo CD requirement (one-time, global):** the restart annotation isn't in git, so Argo may report OutOfSync. Add to
`argocd-cm`:

```yaml
resource.customizations.ignoreDifferences.all: |
  jsonPointers:
  - /spec/template/metadata/annotations/kubectl.kubernetes.io~1restartedAt
```

If an Argo sync later drops the annotation (e.g. `Replace=true`), the template changes again and Pods restart once more,
still rewritten. That's harmless. Flux behaviour is unverified.

### 7.3 Timing

- `timeoutSeconds` is at most 30 s; on timeout the request is admitted (`failurePolicy: Ignore`). The mutating webhook only reads memory (ms).
  The validating webhook uses `timeoutSeconds: 25` and answers on its own after a 20 s scan budget, so users see
  Hedgehog's message instead of `context deadline exceeded`.
- tag → digest: mutating uses the tag → digest pairs seen on running Pods, with no registry calls; a miss means "not rewritten". Validating
  resolves tags in the registry only in active mode, for images it doesn't know.

### 7.4 Availability

Hedgehog is one Pod, so it will be down during restarts, upgrades and node drains (including PV reattachment, which
can take minutes). Both webhooks are always `failurePolicy: Ignore`: while Hedgehog is down, everything is admitted
as it is, in either mode. Known-vulnerable images get through, and new Pods of patched workloads aren't rewritten,
for the duration. Hedgehog never blocks the cluster because it's unavailable. Once it's back, the reconcile loop finds
the Pods not on the current patch and restarts their workloads (§7.2); new never-seen images are caught by the background scan.

- Namespaces in `EXCLUDE_NAMESPACES` (the manifest uses `kube-system,hedgehog-system`) are left alone entirely: not
  tracked, scanned, patched or restarted, and the webhooks allow them without checks. The webhooks have no
  `namespaceSelector`; this list is the only exclusion, applied by the handlers.
- Admission comes up before anything else on start: the snapshot is built from the bbolt file and the Pod informer,
  before the vulnerability DB update or any scanning.
- **Break-glass:** a cluster admin deletes the two webhook configurations. That's also the only way past the hard deny
  (e.g. Argo `Replace=true`, or recreating an app in disaster recovery, which turns updates into DELETE + CREATE).

### 7.5 Argo CD

- **Rewrites:** Argo diffs workloads, not Pods, so rewritten Pods cause no OutOfSync. The restart annotation is
  covered by the global ignore rule (§7.2).
- **Denial:** that resource's apply fails, the sync operation ends **Failed**, earlier resources in the wave stay applied,
  and later waves don't run. The UI shows Hedgehog's message.
- **Retries:** automated sync never re-attempts the same revision after a failure. Only `syncPolicy.retry`, a new commit,
  or a manual sync starts a new attempt. `selfHeal` doesn't retry failed syncs.

| Denial | Clears by itself? | Argo outcome |
|---|---|---|
| Known actionable image | No | Sync Failed until a commit ships a fixed image. Intended |
| "Scanning, retry" (active mode only) | Yes, ~1 min | Recovers only with `syncPolicy.retry` (e.g. `limit: 5, duration: 15s, factor: 2`); otherwise on the next commit or a manual sync |
| Pod-level deny | Usually (when the patch is ready) | The sync **Succeeded**; health goes Progressing → Degraded |
| Failed rollout | No | Synced, Degraded |

- **Allowed re-applies:** unchanged manifests, tracking labels, and commits that only change non-workload resources. The
  template comparison must be semantic (after defaulting).

## 8. Observability

- Prometheus metrics: mode (idle/active), active rewrites, actionable images, patch results, restarts by result,
  admission decisions by reason, scan latency.
- A read-only HTTP status endpoint on the controller (`/status`: findings, rewrites, users, and workloads still running a patched image's source digest), plus structured logs.
- Admission messages name the image, CVEs, risk and fix version, since that's where most people will see them.

## 9. Phases

1. **P0:** inventory, scanner, bbolt/PV, DB-update re-matching, scope filter, metrics, `/status`.
2. **P1:** webhooks with idle/active modes, hard deny, inline scan in active mode.
3. **P2:** grype→copa, rootless buildkitd, patch, push, scan of the patched image.
4. **P3:** node runtime replacement.
5. **P4:** Pod rewrite, restart annotation.

## 10. Risks

- **Major runtime bumps break apps.** The native rollout stalls on unready Pods; the rewrite stays (fails closed).
- **Single-Pod availability:** while Hedgehog is down, nothing is checked or rewritten (§7.4).
- **Idle-mode exposure window** for never-seen vulnerable images (§7.1).
- **Risk inputs change daily** (KEV, EPSS), so mitigations can start at any time, with no human involved.
- **Hedgehog is a privileged image factory.** Pin tools, verify every download, and restrict access to `hedgehog-system`
  and the push credentials.

## Appendix A — Exploitability metrics

| Metric | What it is | Notes |
|---|---|---|
| **Severity (CVSS)** | How bad *if* exploited. Critical = CVSS ≥ 9.0 | Says nothing about likelihood; node:22 has 57 Criticals, none in scope |
| **EPSS score** | FIRST.org probability of exploitation activity in the next 30 days, 0–1, daily | A model; can lag new exploits |
| **EPSS percentile** | Rank among all CVEs | Skewed: a 6% probability is the 93.6th percentile |
| **KEV** | CISA catalogue of CVEs confirmed exploited in the wild (`knownExploited`, incl. `knownRansomwareCampaignUse`) | Strongest signal; trails real events |
| **grype `risk`** | `min(threat × severity × kevMod, 1) × 100`. threat = 1.0 if KEV else EPSS. severity = mean(label/10, mean CVSS/10), label Critical = 9.0. kevMod = 1.1 (KEV + ransomware) / 1.05 (KEV) / 1.0. Source: `grype/vulnerability/metadata.go` v0.122.1; matches grype's output exactly | **The gate: `risk > 90`** |
