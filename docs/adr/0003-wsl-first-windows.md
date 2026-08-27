# ADR 0003: WSL-first Windows topology

**Status:** Accepted  
**Date:** 2026-08-23

On Windows, the repository, Python control plane, Git, and OCI commands run inside WSL 2. PowerShell invokes the WSL CLI with structured arguments. Native Windows remains a portability-test surface, not the canonical evaluator topology.
