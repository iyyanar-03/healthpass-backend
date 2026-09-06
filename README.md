# HealthPass backend

This API uses SQLite on a laptop and PostgreSQL when Railway supplies the
`DATABASE_URL` environment variable.

## Railway deployment (persistent cloud data)

1. Create a GitHub repository and upload the **contents** of this
   `healthpass-backend` folder to its root.
2. At [Railway](https://railway.app/), create a project and choose **Deploy from
   GitHub Repo**. Select that repository.
3. In the same Railway project, choose **New → Database → PostgreSQL**.
4. Open the API service → **Variables** → add `DATABASE_URL` and set its value
   to `${{Postgres.DATABASE_URL}}`. The database service name may differ; use
   the exact PostgreSQL service name shown by Railway.
5. Open API service → **Settings → Networking** → **Generate Domain**.
6. Open `https://YOUR-RAILWAY-DOMAIN/health`; it must return
   `{"status":"ok"}`.

Use the resulting `https://...` domain when building the Flutter APK:

```cmd
flutter build apk --release --dart-define=API_BASE_URL=https://YOUR-RAILWAY-DOMAIN
```

Do not use the laptop Wi-Fi IP or `127.0.0.1` after cloud deployment.

## Local setup (Windows)

1. Confirm Python is available with `python --version`.
2. Open Command Prompt in this folder and run:

```cmd
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

3. Verify it in a browser: `http://127.0.0.1:8000/docs`.

The SQLite database is created as `healthpass.db` after the service first starts.

## Endpoints

- `POST /api/v1/auth/register`
- `POST /api/v1/auth/login`
- `GET /api/v1/patients/me`
- `PUT /api/v1/patients/me`

## Before phone testing

Use your laptop's Wi-Fi IPv4 address (for example `http://192.168.1.5:8000`), not
`localhost`, when the app runs on your phone. The phone and laptop must be on the
same Wi-Fi network. Windows Firewall will need an inbound allow rule for port 8000.
