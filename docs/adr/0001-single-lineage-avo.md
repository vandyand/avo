# ADR 0001: Single-lineage agentic variation first

**Status:** Accepted  
**Date:** 2026-08-23

V1 implements one committed lineage and one active variation session per run. The harness controls private attempts; independent evaluation and admission remain outside it. This isolates the agentic operator before archive and concurrency behavior. Population methods require the `SearchStrategy` port, equal-budget comparison, and a new ADR.
