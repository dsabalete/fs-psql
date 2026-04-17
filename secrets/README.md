# Secrets for production compose

These files are used by Docker secrets in `docker-compose.yml`.

Required files:

- `secrets/postgres_password.txt`
- `secrets/pgadmin_password.txt`

Notes:

- Keep strong passwords and do not commit real secrets.
- `.gitignore` is configured to ignore `secrets/*.txt`.
- You can copy from `*.example` files and replace values.
