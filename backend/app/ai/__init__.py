"""
MailRecon AI intelligence module.
Provides abstract, mock, and Gemini AI providers for forensic incident briefings.
"""
from typing import Optional

from app.ai.base import AIAnalysisResult, BaseAIProvider
from app.ai.gemini import GeminiAIProvider
from app.ai.mock import MockAIProvider
from app.config import settings

_provider_instance: Optional[BaseAIProvider] = None


def get_ai_provider() -> BaseAIProvider:
    """Factory retrieving the configured AI provider singleton."""
    global _provider_instance
    if _provider_instance is None:
        provider_name = (settings.AI_PROVIDER or "mock").lower().strip()
        if provider_name == "gemini":
            _provider_instance = GeminiAIProvider()
        else:
            _provider_instance = MockAIProvider()
    return _provider_instance


def set_ai_provider(provider: BaseAIProvider):
    """Override AI provider instance (useful for testing)."""
    global _provider_instance
    _provider_instance = provider
