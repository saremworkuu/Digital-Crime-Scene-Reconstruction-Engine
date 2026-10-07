# Configuration settings
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    DATABASE_URL: str
    SECRET_KEY: str
    ALGORITHM:str="HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int=30

    CORS_ORIGINS: str="http://localhost:3000"

    MAX_UPLOADS_SIZE:int=104857600

    UPLOAD_DIR:str="uploads"

    model_config=SettingsConfigDict(
        env_file=".env",
        extra="ignore"
    )

settings=Settings()