# ADR 0002: Explicit state machine before workflow frameworks

**Status:** Accepted  
**Date:** 2026-08-23

Closed transition tables and persisted domain records are authoritative. External work is journaled as idempotent activities. Temporal and DBOS may orchestrate transitions later but cannot become the domain source of truth.
