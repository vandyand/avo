AVO completion semantics for this comparison:

- Return `outcome: "proposal"` when you changed the candidate workspace and believe it is ready for independent evaluation.
- Return `outcome: "stop"` only when you are intentionally producing no candidate because the task cannot be completed safely within the constraints.
- Completing the implementation and public tests is not a reason to return `stop`; it is the condition for returning `proposal`.
- List only tests you actually ran in `claimed_tests`.
