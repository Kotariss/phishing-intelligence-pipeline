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

    # LLM / VLM — required: lure text, image and brand judgements come from the model. Any OpenAI-compatible
    # chat-completions endpoint.
    #   LLM_MODE=off   -> no model: structural extractors only (URL, DOM, forms, attachments, QR, headers); every result is marked llm_mode=off
    #   LLM_MODE=local -> local server without key, no external network: the `llm` Ollama container of
    #                     docker-compose (http://llm:11434/v1), or Ollama / LM Studio / vLLM on the host
    #   LLM_MODE=cloud -> remote endpoint authorised with an API key
    # Each mode has its own models: a cloud model name does not exist on the local server and vice versa.
    LLM_MODE: str = "local"
    LLM_LOCAL_BASE_URL: str = "http://localhost:11434/v1"
    LLM_LOCAL_API_KEY: str = ""
    LLM_LOCAL_TEXT_MODEL: str = "qwen3-vl:2b-instruct"
    LLM_LOCAL_VISION_MODEL: str = "qwen3-vl:2b-instruct"
    LLM_CLOUD_BASE_URL: str = ""
    LLM_CLOUD_API_KEY: str = ""
    LLM_CLOUD_TEXT_MODEL: str = ""
    LLM_CLOUD_VISION_MODEL: str = ""
    # Sent as `reasoning_effort` when set (e.g. "none"). Not set by default: the cloud model answers the
    # lure question correctly only with its reasoning (3-4 s per call); the local `-instruct` models do not
    # reason at all. A local "thinking" model would need "none": on CPU its hidden reasoning takes minutes.
    LLM_REASONING_EFFORT: str = ""
    # Output budget per call. Reasoning tokens of a thinking model count against it: the short JSON
    # answers need ~100 tokens, the cloud model's reasoning occasionally 1-2 thousand.
    LLM_MAX_TOKENS: int = 4000
    LLM_TEMPERATURE: float = 0.1
    LLM_TIMEOUT_SECONDS: int = 60
    # A failed call is retried with growing pauses; after the last attempt the object is skipped (reported).
    LLM_ATTEMPTS: int = 4

    # Security & Thresholds
    ANTI_SSRF_ENABLED: bool = True
    SANDBOX_TIMEOUT_SECONDS: int = 10
    SCORE_CLEAN_THRESHOLD: float = 0.30
    SCORE_MALICIOUS_THRESHOLD: float = 0.70

    # Exports
    EXPORTS_DIR: str = Field(
        default_factory=lambda: os.path.join(os.getcwd(), "exports")
    )
    DATASET_DIR: str = Field(
        default_factory=lambda: os.path.join(_REPO_ROOT, "file_for_case") if os.path.isdir(os.path.join(_REPO_ROOT, "file_for_case"))
        else os.path.join(os.getcwd(), "file_for_case")
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
        mode = (self.LLM_MODE or "local").strip().lower()
        return mode if mode in ("local", "cloud", "off") else "local"

    @property
    def llm_enabled(self) -> bool:
        """False in LLM_MODE=off: only the structural extractors run (ТЗ 4.4.2: the model is optional, 7.11)."""
        return self.llm_mode != "off"

    @property
    def llm_base_url(self) -> str:
        return self.LLM_CLOUD_BASE_URL if self.llm_mode == "cloud" else self.LLM_LOCAL_BASE_URL

    @property
    def llm_api_key(self) -> str:
        return self.LLM_CLOUD_API_KEY if self.llm_mode == "cloud" else self.LLM_LOCAL_API_KEY

    @property
    def text_model(self) -> str:
        return self.LLM_CLOUD_TEXT_MODEL if self.llm_mode == "cloud" else self.LLM_LOCAL_TEXT_MODEL

    @property
    def vision_model(self) -> str:
        """Image model of the active mode; a multimodal text model serves both when none is set."""
        if self.llm_mode == "cloud":
            return self.LLM_CLOUD_VISION_MODEL or self.LLM_CLOUD_TEXT_MODEL
        return self.LLM_LOCAL_VISION_MODEL or self.LLM_LOCAL_TEXT_MODEL

    def llm_config_problem(self) -> str:
        """Empty when the model of the active mode is fully configured, otherwise what is missing."""
        if not self.llm_enabled:
            return ""
        if self.llm_mode == "cloud":
            missing = [n for n, v in (("LLM_CLOUD_BASE_URL", self.LLM_CLOUD_BASE_URL), ("LLM_CLOUD_API_KEY", self.LLM_CLOUD_API_KEY),
                                      ("LLM_CLOUD_TEXT_MODEL", self.LLM_CLOUD_TEXT_MODEL)) if not v]
        else:
            missing = [n for n, v in (("LLM_LOCAL_BASE_URL", self.LLM_LOCAL_BASE_URL),
                                      ("LLM_LOCAL_TEXT_MODEL", self.LLM_LOCAL_TEXT_MODEL)) if not v]
        return f"LLM_MODE={self.llm_mode}: not set {', '.join(missing)}" if missing else ""


_settings: Settings = None

def get_settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings
