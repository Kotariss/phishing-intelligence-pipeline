import os
from pydantic_settings import BaseSettings
from pydantic import Field

class Settings(BaseSettings):
    # Service Endpoints
    WORKER_HOST: str = "0.0.0.0"
    WORKER_PORT: int = 8000
    SANDBOX_HOST: str = "localhost"
    SANDBOX_PORT: int = 8001
    
    # Database
    DATABASE_URL: str = Field(
        default_factory=lambda: os.getenv("DATABASE_URL", "sqlite:///./pipeline.db")
    )

    # LLM Settings
    LLM_BASE_URL: str = Field(
        default_factory=lambda: os.getenv("LLM_BASE_URL", "https://your-llm-endpoint.example/api")
    )
    LLM_API_KEY: str = Field(
        default_factory=lambda: os.getenv("LLM_API_KEY", "")
    )
    LLM_TEXT_MODEL: str = Field(
        default_factory=lambda: os.getenv("LLM_TEXT_MODEL", "deepseek-ai/DeepSeek-V4-Flash-0731")
    )
    LLM_VISION_MODEL: str = Field(
        default_factory=lambda: os.getenv("LLM_VISION_MODEL", "Qwen3.8-27B")
    )
    LLM_TEMPERATURE: float = 0.1
    LLM_TIMEOUT_SECONDS: int = 45

    # Ollama
    OLLAMA_BASE_URL: str = "http://localhost:11434/v1"
    OLLAMA_ENABLED: bool = False

    # Security & Thresholds
    ANTI_SSRF_ENABLED: bool = True
    SANDBOX_TIMEOUT_SECONDS: int = 10
    SCORE_CLEAN_THRESHOLD: float = 0.30
    SCORE_MALICIOUS_THRESHOLD: float = 0.70

    # Exports
    EXPORTS_DIR: str = Field(
        default_factory=lambda: os.path.join(os.getcwd(), "exports")
    )

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "extra": "ignore"
    }


_settings: Settings = None

def get_settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings
