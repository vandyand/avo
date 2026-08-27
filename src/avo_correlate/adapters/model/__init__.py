"""Model gateway adapters."""

from avo_correlate.adapters.model.http import StructuredHttpModelGateway
from avo_correlate.adapters.model.openai_compatible import (
    OpenAICompatibleModelGateway,
    OpenAICompatibleStructuredInference,
)
from avo_correlate.adapters.model.openrouter import (
    OpenRouterModelGateway,
    OpenRouterStructuredInference,
)
from avo_correlate.adapters.model.recorded import RecordedModelGateway

__all__ = [
    "OpenAICompatibleModelGateway",
    "OpenAICompatibleStructuredInference",
    "OpenRouterModelGateway",
    "OpenRouterStructuredInference",
    "RecordedModelGateway",
    "StructuredHttpModelGateway",
]
