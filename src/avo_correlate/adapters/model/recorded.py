"""Deterministic structured model gateway for replay and recovery tests."""

from collections import deque

from avo_correlate.contracts.agent import AgentContext, AgentTurn


class RecordedModelExhausted(RuntimeError):
    pass


class RecordedModelGateway:
    def __init__(self, turns: list[AgentTurn]) -> None:
        self._turns = deque(turns)
        self.contexts: list[AgentContext] = []

    async def next_turn(self, context: AgentContext) -> AgentTurn:
        self.contexts.append(context)
        if not self._turns:
            raise RecordedModelExhausted("recorded model has no remaining turn")
        return self._turns.popleft()
