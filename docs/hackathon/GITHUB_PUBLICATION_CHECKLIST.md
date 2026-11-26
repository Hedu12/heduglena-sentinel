# GitHub publication checklist — HEDUGLENA Sentinel

**Prepared:** 2026-11-26 · **Kiroween deadline:** 2026-12-04 14:00 PT (2026-12-05 01:00 EAT)
**Current state:** everything is committed locally on `feature/phase2-runtime-orchestrator`
(`77e3161`). `main` is at `469f953`, with no remote, no push and no tag.

Tick each box as you go. Steps marked **(Henok)** need your decision or your GitHub account.

## A. Already verified locally (2026-11-26)

- [x] 270 files in the committed tree; the whole history is ~0.76 MB, with no large files and no LFS needed.
- [x] No secrets, `.env`, databases, model files, logs, virtual environments, `node_modules`,
  `dist` or coverage output are tracked. The only scan hits are deliberate fake values in
  redaction tests.
- [x] `.gitignore` excludes local artifacts: `sentinel.db`, demo-session archives, venvs,
  caches and benchmark reports.
- [x] `/.kiro` is tracked (14 files: spec, steering, hooks) and is **not** git-ignored, as the
  Kiroween rules require.
- [x] `LICENSE` is the standard MIT text, so GitHub should detect it.
- [x] All 8 protected files match their pinned hashes.
- [x] Tests:
  - backend: 2,114 passed
  - frontend: 60 passed
  - `tsc`, ESLint and the CSP check pass
  - smoke test Normal → Suspicious → Reset → Critical passed twice
- [x] `main` can be fast-forwarded: the 4 commits on the feature branch descend from it
  directly.

## B. Decisions before the first push **(Henok)**

- [ ] **Commit email privacy.** All commits record your personal Gmail address as the author.
  Pushing makes it public. Choose one:
  - **(a) Keep it.** No action needed.
  - **(b) Use GitHub's private address.** Copy your `…@users.noreply.github.com` address
    (GitHub → Settings → Emails), set `git config user.email` to it, and rewrite the 4
    unpublished commits **before** the first push. Rewriting is safe only before
    publication, and I'd do it only on your explicit request.
- [ ] **Repository name and owner.** For example `<your-account>/heduglena-sentinel`.
- [ ] **Visibility timing.** Keep it private until the submission is ready, or make it public
  now. The rules require it to be **public** and open source by the deadline.
- [ ] **Branches to publish.** Recommended: `main` only, after the fast-forward in §C. The
  feature and Phase 1 branches add nothing beyond `main`.
- [ ] **Application URL for Devpost.** The rules ask for "a URL to your functional
  application(s)". There is no hosted instance; the repo, local install and video are the
  current plan. Ask the Devpost organizers whether that suffices, or decide on hosting.
- [ ] **Docker.** It does not work yet (README says so). Either leave it documented as such, or
  approve a separate fix before publishing.

## C. Publish (each step needs approval)

The GitHub CLI (`gh`) is not installed, so these steps use the web UI and plain `git`. Git for
Windows opens a browser sign-in on the first push.

1. [ ] **Create an empty repository** on github.com **(Henok)**.
   - Do **not** add a README, `.gitignore` or license there; they already exist locally, and
     adding them would create a conflicting first commit.
2. [ ] **Fast-forward `main`** to the release commit. This moves no other branch.
   ```bash
   git switch main
   git merge --ff-only feature/phase2-runtime-orchestrator   # main -> 77e3161
   ```
3. [ ] **Final local check** on `main`:
   - `git status --short` is empty.
   - The protected-hash test passes: `cd backend && python -m pytest tests/security/test_protected_files.py`.
4. [ ] **Add the remote and push `main`:**
   ```bash
   git remote add origin https://github.com/<your-account>/heduglena-sentinel.git
   git push -u origin main
   ```
5. [ ] **Optionally tag the submission** once the video and Devpost entry are final:
   `git tag -a kiroween-2026 -m "Kiroween 2026 submission" && git push origin kiroween-2026`.

## D. Verify on GitHub after the push

- [ ] **About panel:** shows **MIT License**. If it doesn't, check that `LICENSE` sits at the
  repository root on `main`.
- [ ] **File count:** 270 tracked files.
- [ ] **Nothing local was uploaded:** none of `sentinel.db`, `node_modules/`, `dist/`, `.venv/`
  or the `reports/phase8.2`–`8.4` folders appear.
- [ ] **Kiro evidence:** `.kiro/specs/heduglena-sentinel/`, `.kiro/steering/` and
  `.kiro/hooks/` are visible.
- [ ] **README renders:** tables and code blocks display, and these links open:
  - `LICENSE`, `docs/hackathon/VISUAL_QA.md`
  - `docs/evaluation/QWEN3_0.6B_CPU_EVALUATION.md`
  - the `.kiro/specs/...` files
- [ ] **Security tab:**
  - **Secret scanning:** no alerts expected.
  - **Dependabot:** alerts for Vite, Vitest, esbuild and tinypool are **expected**. They are
    dev and test tooling only, and the upgrade is deferred by decision, as documented in the
    README. Do not let Dependabot open automatic upgrade PRs before the deadline.
- [ ] **Repository settings:**
  - description, e.g. "Adaptive, explainable cyber-defense prototype (Kiroween 2026)"
  - topics: `kiro`, `kiroween`, `cybersecurity`, `fastapi`, `react`
  - website: only once a demo URL exists

## E. Fresh-clone test (before submitting)

On a clean folder, ideally a second machine:

- [ ] `git clone https://github.com/<your-account>/heduglena-sentinel.git`
- [ ] **Backend:** `cd backend`, create a venv, `pip install -e ".[dev]"`, then run `pytest`.
  Expect 2,112 passed and 2 skipped: the skipped tests need the local benchmark reports, which
  are not published.
- [ ] **Frontend:** `cd frontend`, then `npm ci`, `npm run typecheck`, `npm run lint`,
  `npm run test`, `npm run build` and `npm run verify:csp`.
- [ ] **Run the demo** from the README: Normal, Suspicious, Reset, Critical. The dashboard
  shows each step, and every response is labeled SIMULATED.
- [ ] **No local data was needed:** the clone creates its own `backend/sentinel.db` on first
  start.

## F. Kiroween submission items that depend on the repository **(Henok)**

From the official rules (kiroween.devpost.com/rules):

- [ ] The repository is **public**, on **GitHub**, with the license detectable in About.
- [ ] `/.kiro` is at the repository root and not git-ignored.
- [ ] The repository contains all source, assets and instructions needed to run the project
  (README quick start).
- [ ] Demo video: **under 3 minutes**, **public on YouTube**, showing the project running,
  with no copyrighted music or third-party marks.
- [ ] Devpost entry:
  - repository URL, video URL and category
  - a text description of features and functionality
  - **how Kiro was used**: spec, steering, hooks, property-based tests; claim nothing that
    was not used
- [ ] Optional bonus posts: blog, or social with `#KiroweenHackathon26` at the start of the post.

## G. Do not

- Push the local database, benchmark reports, virtual environments or `node_modules`.
- Rewrite history **after** publication.
- Force-push `main`.
- Accept automatic dependency-upgrade PRs before the deadline.
- Change protected security files, thresholds or the AI boundary while preparing the release.
