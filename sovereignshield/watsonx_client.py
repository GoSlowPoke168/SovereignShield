import os
from dotenv import load_dotenv
from ibm_watsonx_ai import Credentials
from ibm_watsonx_ai.foundation_models import ModelInference

from . import config

load_dotenv()

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


def get_model(model_id: str = config.DEFAULT_MODEL) -> ModelInference:
    """
    Return a configured ModelInference instance for the given model ID.
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
        params=config.MODEL_PARAMS,
    )
