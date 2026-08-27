# Git baseline and recovery rehearsal

AVO's controlling repository is an operator-managed trust anchor. Candidate
workspaces remain VCS-free and must never be initialized or connected to the
controlling remote by an agent.

## Record a baseline

From the controlling repository root, first confirm the intended remote and
branch with the repository administrator. Then run the read-only verifier:

```powershell
python scripts/verify_git_baseline.py `
  --root . `
  --expected-branch main `
  --expected-remote https://github.com/OWNER/REPOSITORY.git
```

Save the JSON output in the approved evidence store. It records the resolved
root, branch, commit object ID, tree object ID, clean status, and a
credential-redacted remote identity. Supplying `--expected-commit` and
`--expected-tree` on later runs turns the saved values into a compare check.
The command is inspection-only: it does not initialize, commit, fetch, push,
or alter Git configuration.

## Recovery rehearsal

Perform this rehearsal on a disposable clone or an operator-approved backup,
never in a candidate workspace:

1. Save a successful verifier JSON document and its evidence-record identifier.
2. Record the commit and tree IDs, remote URL (without credentials), and branch.
3. Recreate a clean checkout at the recorded commit using the organization's
   approved backup/clone procedure.
4. Run the verifier against the recreated checkout, passing the recorded
   commit and tree as `--expected-commit` and `--expected-tree`.
5. Compare the resulting JSON fields to the saved evidence and retain both
   records, including the command date and operator identity.
6. If any check fails, stop promotion and escalate; do not repair the baseline
   by rewriting history or changing the expected digest.

The local verifier proves repository-root identity, clean working state,
commit/tree identity, branch, and configured remote identity. It cannot prove
that a remote branch is protected, that required checks are enabled, or that
the remote's access policy is unchanged. Those claims require separately
exported, authenticated provider evidence. If such a document is supplied via
`--protection-evidence`, it must be JSON declaring `source` as `remote`, the
matching branch and remote, and `protected: true`; retain that document beside
the local JSON and record its provider timestamp and request/audit identifier.
