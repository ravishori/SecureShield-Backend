from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # Database
    DATABASE_URL: str = "postgresql+asyncpg://postgres:London2026@localhost:5432/SecureShieldDB"

    # Auth
    SECRET_KEY: str = "secureshield-secret-key-change-in-prod"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24
    REFRESH_TOKEN_EXPIRE_DAYS: int = 30

    # AI
    ANTHROPIC_API_KEY: str = ""

    # EMAIL (SMTP)
    SMTP_HOST: str = "smtp.gmail.com"
    SMTP_PORT: int = 587
    SMTP_USER: str = "ravishori@gmail.com"
    SMTP_PASSWORD: str = "fwsg dwxx jmas biqq"          # Gmail App Password
    SMTP_FROM_EMAIL: str = "SecureShield AI <ravishori@gmail.com>"
    ERROR_NOTIFY_EMAIL: str = "ravishori@gmail.com"

    # TWILIO (SMS + WhatsApp)
    TWILIO_ACCOUNT_SID: str = "AC71b0fbdb1e4adfdac3533b1d8d0be1c2"
    TWILIO_AUTH_TOKEN: str = "ed361570b6890ea6f1ef9e039bcfe846"
    TWILIO_SMS_NUMBER: str = "+18655188663"              # plain E.164 for SMS
    TWILIO_WHATSAPP_NUMBER: str = "whatsapp:+18655188663"  # WhatsApp sandbox

    # RATE LIMITING
    OTP_SEND_LIMIT: int = 5        # max OTP sends per identifier per hour
    OTP_VERIFY_LIMIT: int = 10     # max verify attempts per identifier per 15 min
    API_RATE_LIMIT: int = 100      # max requests per IP per minute

    # SECURITY
    LOG_RETENTION_DAYS: int = 90   # auto-delete error logs older than this

    class Config:
        env_file = ".env"
        extra = "ignore"


settings = Settings()
