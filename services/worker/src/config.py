import os
from pydantic_settings import BaseSettings
from pydantic import Field

# Repository root: services/worker/src -> ../../.. ; inside Docker the layout is /app/src.
_SRC_DIR = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.abspath(os.path.join(_SRC_DIR, "..", "..", ".."))


def _default_env_file() -> str:
    candidate = os.path.join(_REPO_ROOT, ".env")
    return candidate if os.path.exists(candidate) else ".env"


class Settings(BaseSettings):
    # Service Endpoints
    WORKER_HOST: str = "0.0.0.0"
    WORKER_PORT: int = 8000
    SANDBOX_HOST: str = "localhost"
    SANDBOX_PORT: int = 8001

    # When the sandbox service is unreachable the worker may fetch URLs / parse files
    # in its own process. This breaks the trusted/untrusted zone separation, so it is
    # disabled by default and must be enabled explicitly for local development.
    SANDBOX_INPROCESS_FALLBACK: bool = False

    # Database
    DATABASE_URL: str = "sqlite:///./pipeline.db"

    # LLM / VLM (optional heavy extractors). Any OpenAI-compatible chat-completions endpoint.
    #   LLM_MODE=local -> local server without key: Ollama (http://localhost:11434/v1),
    #                     LM Studio (http://localhost:1234/v1), vLLM, llama.cpp server, ...
    #   LLM_MODE=cloud -> remote endpoint authorised with an API key
    #   LLM_MODE=off   -> pipeline works with deterministic extractors only
    LLM_MODE: str = "local"
    LLM_LOCAL_BASE_URL: str = "http://localhost:11434/v1"
    LLM_LOCAL_API_KEY: str = ""
    LLM_CLOUD_BASE_URL: str = ""
    LLM_CLOUD_API_KEY: str = ""
    LLM_TEXT_MODEL: str = "qwen2.5:7b"
    LLM_VISION_MODEL: str = "qwen2.5vl:7b"
    LLM_TEMPERATURE: float = 0.1
    LLM_TIMEOUT_SECONDS: int = 60

    # Security & Thresholds
    ANTI_SSRF_ENABLED: bool = True
    SANDBOX_TIMEOUT_SECONDS: int = 10
    SCORE_CLEAN_THRESHOLD: float = 0.30
    SCORE_MALICIOUS_THRESHOLD: float = 0.70

    # Exports
    EXPORTS_DIR: str = Field(
        default_factory=lambda: os.path.join(os.getcwd(), "exports")
    )
    LOGS_DIR: str = Field(
        default_factory=lambda: os.path.join(os.getcwd(), "logs")
    )

    model_config = {
        "env_file": _default_env_file(),
        "env_file_encoding": "utf-8",
        "extra": "ignore"
    }

    @property
    def llm_mode(self) -> str:
        mode = (self.LLM_MODE or "off").strip().lower()
        return mode if mode in ("local", "cloud", "off") else "off"

    @property
    def llm_base_url(self) -> str:
        return self.LLM_CLOUD_BASE_URL if self.llm_mode == "cloud" else self.LLM_LOCAL_BASE_URL

    @property
    def llm_api_key(self) -> str:
        return self.LLM_CLOUD_API_KEY if self.llm_mode == "cloud" else self.LLM_LOCAL_API_KEY

    @property
    def llm_configured(self) -> bool:
        if self.llm_mode == "off":
            return False
        if self.llm_mode == "cloud":
            return bool(self.LLM_CLOUD_BASE_URL and self.LLM_CLOUD_API_KEY)
        return bool(self.LLM_LOCAL_BASE_URL)


_settings: Settings = None

def get_settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings


def reset_settings() -> None:
    """Drops the cached settings (used by tests that tweak environment variables)."""
    global _settings
    _settings = None
