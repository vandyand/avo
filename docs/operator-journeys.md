# Operator journey contract

## Primary user and job

A developer or technical operator validates an experiment, starts a bounded run, understands its current state and cost, and safely recovers or stops when work cannot continue.

| Field | Requirement |
|---|---|
| Trigger | The operator has a workspace and experiment specification. |
| Entry | `avoctl doctor` and `avoctl experiment validate` establish readiness before mutation. |
| Orient | Status names the run state, champion, budget remaining, active work, and blockers. |
| Act | Start is primary from `ready`. Pause and cancel are commands, not state toggles. |
| Feedback | Mutations return the accepted command, resulting or pending state, and event sequence. |
| Completion | `completed` identifies the stopping rule and champion; terminal failures explain why work stopped. |
| Next action | Inspect provenance, resume, satisfy a review, or create a revised experiment. |
| Recovery | Idempotency keys make retries safe; event cursors recover after disconnect. |

## Required states

- **Empty:** show validation and creation commands.
- **In progress:** show last durable boundary, current reservation, and pause action.
- **Paused:** show why and whether resume is permitted.
- **Blocked:** name the required role or evidence.
- **Failed:** distinguish candidate failure from infrastructure failure.
- **Cancelled:** confirm that no later admission is possible.
- **Completed:** name the champion and provenance verification command.
- **Denied:** show a stable policy reason code without leaking policy inputs.

## Language contract

An **attempt** is private search work. A **candidate** is a frozen proposal. **Admission** creates a lineage entry. **Quarantine** means evaluation was inconclusive, not that the candidate failed.

Human output always includes a safe next action when one exists.
