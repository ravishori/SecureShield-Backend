// Railway infrastructure-as-code for the SecureShield staging project (replaces railway.toml,
// which Railway no longer applies). Secrets are never written here: every variable is preserve().
//   * source.checkSuites: false -> deploys are NOT gated on CI. true would block every deploy: the
//     repo has GitHub apps (render, cursor) whose empty check suites stay "queued" forever.
//   * preDeploy                 -> `alembic upgrade head` runs before each new version starts
//   * healthcheck               -> the new version must answer /health before traffic switches
// Review with `railway config plan` before `railway config apply`.
import { defineRailway, github, postgres, preserve, project, service, volume } from "railway/iac";

export default defineRailway(() => {
  const Postgres = postgres("Postgres", { region: "europe-west4-drams3a" });
  const secureshieldApiVolume = volume("secureshield-api-volume", { alerts: { usage: { "100": {}, "80": {}, "95": {} } }, allowOnlineResize: true, region: "europe-west4-drams3a", sizeMB: 5000 });
  const postgresVolume = volume("postgres-volume", { alerts: { usage: { "100": {}, "80": {}, "95": {} } }, allowOnlineResize: true, region: "europe-west4-drams3a", sizeMB: 5000 });
  const secureshieldApi = service("secureshield-api", {
    source: github("ravishori/SecureShield-Backend", { branch: "staging/railway-snapshot", checkSuites: false }),
    replicas: { "europe-west4-drams3a": 1 },
    healthcheck: "/health",
    healthcheckTimeout: 60,
    preDeploy: "alembic upgrade head",
    volumeMounts: { "/app/uploads": secureshieldApiVolume },
    env: { ACCESS_TOKEN_EXPIRE_MINUTES: preserve(), ADMIN_TOKEN: preserve(), ALGORITHM: preserve(), ANTHROPIC_API_KEY: preserve(), APP_DB_PASSWORD: preserve(), DATABASE_URL: preserve(), ENVIRONMENT: preserve(), ERROR_NOTIFY_EMAIL: preserve(), GOOGLE_SAFE_BROWSING_API_KEY: preserve(), MIGRATOR_DATABASE_URL: preserve(), MIGRATOR_DB_PASSWORD: preserve(), REFRESH_TOKEN_EXPIRE_DAYS: preserve(), SECRET_KEY: preserve(), SMTP_FROM_EMAIL: preserve(), SMTP_HOST: preserve(), SMTP_PASSWORD: preserve(), SMTP_PORT: preserve(), SMTP_USER: preserve(), SQL_ECHO: preserve(), TWILIO_ACCOUNT_SID: preserve(), TWILIO_AUTH_TOKEN: preserve(), TWILIO_SMS_NUMBER: preserve(), TWILIO_WHATSAPP_NUMBER: preserve() },
  });

  return project("secureshield-staging", {
    resources: [Postgres, secureshieldApi, secureshieldApiVolume, postgresVolume],
  });
});
