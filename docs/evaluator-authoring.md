# Evaluator authoring contract

Evaluator packages are executable specifications and security-sensitive inputs.

- `development` is callable by the harness.
- `admission` is hidden and control-plane invoked.
- `audit` is unavailable during the active run.

Private fixtures must not exist in development image layers. Every evaluator writes one bounded UTF-8 JSON document to `/output/report.json`. Duplicate keys, NaN, infinity, unknown fields, undeclared metrics, invalid digests, and oversized output are rejected.

`failed` is evidence about candidate quality. `errored`, `timed_out`, `invalid_report`, and `policy_blocked` are inconclusive and quarantine the candidate or trigger a bounded retry.

The reference package is in `evaluators/reference`. Build each tier independently with `--provenance=false`; this keeps the content manifest stable while avoiding a time-varying local attestation manifest:

~~~text
docker build --provenance=false --build-arg SOURCE_DATE_EPOCH=0 --file evaluators/reference/Dockerfile.development --tag avo-reference-development:1.0.0 .
docker build --provenance=false --build-arg SOURCE_DATE_EPOCH=0 --file evaluators/reference/Dockerfile.admission --tag avo-reference-admission:1.0.0 .
~~~

The reviewed content manifests are:

- development: `sha256:5ba02af1ac5ff009ec5b046f0e68827a1b157b498d013135227b975d5d2eab17`
- admission: `sha256:a88354382825ac424253e80b11975da5a5d5fc1016d8c91ffb9d8d67fe904ea9`

The development Dockerfile copies only the development partition; the admission Dockerfile copies only the private partition. Dockerfile-specific ignore files also limit each build context to its own partition and the shared entrypoint, so a development build never sends the private suite to the builder. The staging phase normalizes modes and timestamps, and `SOURCE_DATE_EPOCH=0` plus disabled provenance makes manifests reproducible across the native and WSL BuildKit frontends. The runtime never mounts `/evaluator` into a harness container. A writable `/output` directory must be empty, store-controlled, and mode-scoped for the container UID; all other mounts are read-only.

Evaluator configuration declares warm-ups, paired trial seeds, aggregation, outlier policy, hardware class, minimum effect, confidence rule, retry classes, output limits, adaptive admission-query budget, failure-detail policy, holdout rotation, and leakage response. Changing one creates a new evaluator package/version and experiment revision.
