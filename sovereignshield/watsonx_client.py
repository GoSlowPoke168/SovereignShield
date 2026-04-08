"""
watsonx_client.py
─────────────────
Central factory for IBM watsonx.ai ModelInference objects.

Model selection:
  • Primary: ibm/granite-4-h-small
    IBM Granite 4.0 H Small — 30B parameter long-context instruct model.
    The most capable "Ready to use" Granite model available in this account.
    Instruction-tuned for complex reasoning and structured output, making it
    ideal for the multi-agent security inspection pipeline.

  • Why not others:
    granite-guardian-3-8b  → safety CLASSIFIER only (Yes/No), not generative
    granite-3-1-8b-base    → base model, no instruction tuning
    granite-8b-code-instruct → code-focused, narrower instruction following

SDK pattern (ibm-watsonx-ai ≥ 1.1):
  • Credentials are passed directly to ModelInference — no APIClient wrapper.
  • A single shared Credentials object is created once (module singleton)
    so every agent invocation reuses auth tokens.
  • Use model.chat(messages=[...]) NOT model.generate_text() — instruct models
    require proper chat message roles to produce structured output.
  • max_tokens (not max_new_tokens) is the correct param for the chat API.
"""

import os
from dotenv import load_dotenv
from ibm_watsonx_ai import Credentials
from ibm_watsonx_ai.foundation_models import ModelInference

load_dotenv()

# ── Model constants ────────────────────────────────────────────────────────────
# granite-4-h-small: IBM's best general-purpose instruct model on this account.
# Supports structured output, Q&A, RAG, and function-calling via the chat() API.
DEFAULT_MODEL = "ibm/granite-4-h-small"

# ── Module-level credentials singleton ────────────────────────────────────────
_credentials: Credentials | None = None


def _get_credentials() -> Credentials:
    global _credentials
    if _credentials is None:
        url = os.getenv("WATSONX_URL", "https://us-south.ml.cloud.ibm.com")
        api_key = os.getenv("WATSONX_API_KEY")
        if not api_key:
            raise EnvironmentError(
                "WATSONX_API_KEY is not set. "
                "Please create a .env file with your IBM Cloud API key."
            )
        _credentials = Credentials(url=url, api_key=api_key)
    return _credentials


def get_model(model_id: str = DEFAULT_MODEL) -> ModelInference:
    """
    Return a configured ModelInference instance for the given model ID.

    Call this once per agent module (at module scope) to avoid repeated
    auth overhead. The default model is ibm/granite-guardian-3-8b — IBM's
    security-focused Granite 3.x instruction-tuned model.
    """
    project_id = os.getenv("WATSONX_PROJECT_ID")
    if not project_id:
        raise EnvironmentError(
            "WATSONX_PROJECT_ID is not set. "
            "Find your project ID: watsonx.ai → project → Manage → General → Details"
        )

    return ModelInference(
        model_id=model_id,
        credentials=_get_credentials(),
        project_id=project_id,
        params={
            "max_tokens": 8192,        # Greatly expanded limit for large WebGoat/JuiceShop payload lists
            "temperature": 0.05,       # Near-deterministic for security verdicts
            "repetition_penalty": 1.1,
            # No stop_sequences — the ``` stop was halting output before the model
            # could emit JSON, producing empty responses.
        },
    )
