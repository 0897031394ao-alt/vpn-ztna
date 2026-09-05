# UI Structure

## Runtime source of truth

The running `api` container uses UI assets from the repository root `app_ui/` directory.

In `docker-compose.yml`:

- `./api` is mounted to `/app`
- `./app_ui` is mounted to `/app/app_ui`

Because of this, all FastAPI/Jinja references to:

`/app/app_ui/templates`

resolve to:

`/opt/vpnztna/app_ui/templates`

on the host.

## Active and legacy directories

Active UI directory:

- `app_ui/templates`
- `app_ui/static`

Legacy archived directory:

- `api/app_ui.legacy/templates`
- `api/app_ui.legacy/static`

The legacy directory is kept only for reference and should not be edited for runtime UI changes.

## Rule for future changes

When changing the admin UI, always edit files under:

- `app_ui/templates`
- `app_ui/static`

Do not patch files under `api/app_ui.legacy`, because they are not used by the running `api` service.

## Verification

Current runtime behavior is consistent with:

- `docker-compose.yml` bind mounts
- `Jinja2Templates(directory="/app/app_ui/templates")` in the API code
- successful restart of the `api` container after moving `api/app_ui` to `api/app_ui.legacy`
