# Dependency inventory

Status date: 2026-08-27. `uv.lock` is the authority for every direct and transitive Python artifact URL plus its exact SHA-256 hash. No dependency may be installed outside the frozen lock in CI or release workflows. The separately provisioned Codex CLI is verified by absolute path and exact version before use and requires an executable checksum in a release-host inventory.

| Component | Exact version | License | Role | Integrity record | Supported hosts | CVE status |
|---|---:|---|---|---|---|---|
| Python | 3.12.10 | PSF-2.0 | Canonical runtime | Official distribution; release checksum required by bootstrap | Linux x86-64; Windows host checks only | Runtime/vendor review required monthly |
| uv | 0.11.14, build `3fdfdc7d4` | Apache-2.0 OR MIT | Resolver and runner | Binary build ID recorded here; Python artifacts frozen in `uv.lock` | Linux/Windows x86-64 | No finding in Python environment scan |
| Alembic | 1.19.1 | MIT | Schema migrations | `uv.lock` artifact hashes | Canonical runtime | No known vulnerability in pip-audit scan |
| FastAPI | 0.141.1 | MIT | Versioned control API | `uv.lock` artifact hashes | Canonical runtime | No known vulnerability in pip-audit scan |
| jsonschema | 4.26.0 | MIT | Exact raw structured-output validation against compiled wire schemas | `uv.lock` artifact hashes | Linux/Windows structured-inference path | No known vulnerability in 2026-08-27 pip-audit scan |
| Pydantic | 2.13.4 | MIT | Boundary validation and schema generation | `uv.lock` artifact hashes | Linux/Windows contract tests | No known vulnerability in pip-audit scan |
| rfc8785 | 0.1.4 | Apache-2.0 | Canonical JSON | `uv.lock` artifact hashes plus canonical fixtures | Linux/Windows contract tests | No known vulnerability in pip-audit scan |
| SQLAlchemy | 2.0.52 | MIT | Persistence adapter | `uv.lock` artifact hashes | Canonical runtime | No known vulnerability in pip-audit scan |
| Typer | 0.27.1 | MIT | Stable CLI | `uv.lock` artifact hashes | Linux/Windows | No known vulnerability in pip-audit scan |
| Uvicorn | 0.52.4 | BSD-3-Clause | Local ASGI server | `uv.lock` artifact hashes | Canonical runtime | No known vulnerability in pip-audit scan |
| httpx2 | 2.12.0 | BSD-3-Clause | API integration tests | `uv.lock` artifact hashes | CI only | No known vulnerability in pip-audit scan |
| Hypothesis | 6.165.10 | MPL-2.0 | Property/security tests | `uv.lock` artifact hashes | CI only | No known vulnerability in pip-audit scan |
| Pyright | 1.1.411 | MIT | Strict static typing | `uv.lock` artifact hashes | CI only | No known vulnerability in pip-audit scan |
| pytest | 9.1.1 | MIT | Test runner | `uv.lock` artifact hashes | CI only | No known vulnerability; upgraded from affected 8.4.2 after `PYSEC-2026-1845` finding |
| pytest-cov | 6.3.0 | MIT | Coverage gate | `uv.lock` artifact hashes | CI only | No known vulnerability in pip-audit scan |
| Ruff | 0.16.4 | MIT | Lint and format gate | `uv.lock` artifact hashes | CI only | No known vulnerability in pip-audit scan |
| OpenAI Codex Python SDK | 0.147.0 | Apache-2.0 | Optional app-server protocol client | `uv.lock` artifact hashes | Linux/WSL live; Windows contract/account checks | Vendor review before pin changes |
| OpenAI Codex CLI | 0.149.1 | Apache-2.0 | Optional coding-agent runtime | Absolute executable path, exact version preflight, release-host checksum required | Linux/WSL live; Windows account check only | Vendor review before pin changes |
| Git | 2.54.0.windows.1 on reviewed host | GPL-2.0-only | Workspace diff and patch executable | OS package provenance; executable checksum required for release host | Linux/Windows host | Host inventory review monthly |
| ripgrep | 15.2.0 | MIT OR Unlicense | Optional search executable | OS package provenance; executable checksum required for release host | Linux/Windows host | Host inventory review monthly |
| Docker Engine/Desktop | 28.5.1 on reviewed host | Apache-2.0; Desktop terms apply | Trusted-team OCI sandbox | Host package provenance | Linux; Windows 11 via WSL 2 | Host inventory and daemon review monthly |
| Python evaluator base | `python:3.12.10-slim-bookworm` | PSF plus Debian package licenses | Tier-separated evaluator image | linux/amd64 manifest `sha256:97983fa8cc88343512862c62307159a82261c3528dc025f79e5a3f7af43e50b4` | OCI linux/amd64 | Rebuild and scan monthly and before release |
| Development evaluator | `avo-reference-development:1.0.0` | Project license plus base-image licenses | Public development evaluation | Reviewed Docker schema-2 manifest `sha256:586dcc790c714be468b38874eeb8e48fca53b9b85b3d3e30f3f70ee526d401b2`, bound config `sha256:25647a31f0af54440a0e9db5ffcf03abec7bda99b41b0b400f5ea056574352c5` | OCI linux/amd64 | Rebuild, verify both digests, and scan before pin changes |
| Admission evaluator | `avo-reference-admission:1.0.0` | Project license plus base-image licenses | Private admission evaluation | Reviewed Docker schema-2 manifest `sha256:972c6afef64519a1f36513d389f62a0d86bb0c7ca10eb53c5eba3103260137c3`, bound config `sha256:1f4812e4b64baa9e14abb59bb939f15cdd4534d4c61b4c4fac274fc7342a4318` | OCI linux/amd64 | Rebuild, verify both digests, and scan before pin changes |

The audit command is:

~~~text
uvx pip-audit --path .venv/Lib/site-packages --format json --output .avo-pip-audit.json
~~~

The 2026-08-27 scan reported no known vulnerabilities across the 47-package all-groups/all-extras environment after adding jsonschema. This is point-in-time evidence, not a guarantee. CI uses `uv sync --all-groups --all-extras --frozen`; monthly review refreshes the advisory scan and evaluator-image scan. Rollback means restoring the prior reviewed `pyproject.toml`, `uv.lock`, and image digest together, then rerunning schema, contract, security, Docker, and end-to-end gates.
