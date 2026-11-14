# Hosted Auth0 MCP endpoint (work in progress)

This branch adds an authenticated HTTP entrypoint **without changing the existing stdio MCP server**.

## Deployment prerequisites — do not deploy until complete

1. Create the Render Web Service and note its final HTTPS URL, for example
   `https://<actual-service>.onrender.com/mcp`. No live URL is known yet.
2. In Auth0, create a **new Custom API** with its **Identifier exactly equal**
   to that final URL. The existing API identifier
   `https://norway-archives-mcp.example/api` is a placeholder and
   **will not work** with the OAuth resource URL ChatGPT uses. Auth0 API
   identifiers cannot simply be edited after creation.
3. On the new API enable RBAC and *Add Permissions in Access Token*; add
   `read:archives`; attach that permission to the Archives Researcher role.
   In the new API's **Application Access** grant the imported ChatGPT
   third-party CIMD client only **User-delegated access** to
   `read:archives`. Do not grant anonymous/client access.
4. The Auth0 tenant has Resource Parameter Compatibility Profile enabled
   and the ChatGPT CIMD client imported. Ensure Google login works for the
   imported ChatGPT app and the user has the Archives Researcher role.
5. Replace the Auth0-development-key Google social connection before
   relying on Google sign-in for production. Confirm that necessary Auth0
   features survive the trial period.

## Render settings (only after the API identifiers are corrected)

Use the code in this branch only after reviewing and merging the PR.
The HTTP start command is:

```sh
python -m norway_archives_mcp.http_server
```

The environment variables are:

- `AUTH0_ISSUER`: `https://<your-auth0-domain>/` (issuer, not a client secret)
- `MCP_PUBLIC_URL`: `https://<actual-render-host>/mcp` (exact resource URL)
- `MCP_HOST`: `0.0.0.0`
- `PORT`: supplied by Render (defaults to 10000)

Install dependencies with `pip install .` or another equivalent build step.

The endpoint exposes:
- `/mcp` — requires valid RS256 JWT issued by the configured Auth0
  domain, with `aud` matching `MCP_PUBLIC_URL` and
  `scope` or `permissions` containing `read:archives`.
- `/.well-known/oauth-protected-resource/mcp` — public OAuth discovery.

The code *fails closed* if required environment variables are missing.
Do not configure Render to deploy a PR branch to a public URL before the
review and tests are complete.

## Validation plan

- Run `pytest -q tests/test_http_auth.py` and the project's full test suite.
- Check that `POST /mcp` without a Bearer token returns HTTP 401
  and an OAuth `WWW-Authenticate` challenge.
- Check that protected-resource metadata shows the correct Auth0 issuer
  and exact public URL.
- Test with real Auth0 JWTs: valid user + scope succeeds, a wrong audience,
  expired token, wrong issuer, invalid signature, and missing scope fail.
- Finally connect the URL in ChatGPT and verify the Google login flow.

The tests bundled with this branch are initial regression tests; they do not
substitute for end-to-end Auth0 verification.
