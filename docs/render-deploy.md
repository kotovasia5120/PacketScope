# Render deployment reference

PacketScope can be deployed to Render as a Docker Web Service. The repository
already contains the complete build input: `Dockerfile`, pinned Python runtime,
offline test command, and application source. No API keys or other secrets are
required.

## Service settings

Use these values when creating or editing the service:

| Render setting | Value |
| --- | --- |
| Service type | Web Service |
| Runtime | Docker |
| Branch | `main` |
| Root Directory | *(empty; repository root)* |
| Dockerfile Path | `./Dockerfile` |
| Docker Build Context Directory | `.` |
| Docker Command | *(empty; use the Dockerfile `CMD`)* |
| Auto-Deploy | On Commit |

The Dockerfile runs `make test` during the image build. The resulting
container starts the server on `0.0.0.0:8765` and exposes the health endpoint
at `/api/health`.

## Verify a deployment

The current public demonstration is:

<https://packetscope-demo.onrender.com>

Check the service without uploading a capture:

```bash
curl --fail https://packetscope-demo.onrender.com/api/health
```

Expected response:

```json
{"status":"ok","local_only":true}
```

The walkthrough video is available at
<https://youtu.be/kQIqGE6kvfc>.

## Privacy note

The hosted service is a public demonstration endpoint. Do not upload
confidential or otherwise sensitive captures to it. Use `make serve` on the
local machine, or run the Docker image bound to localhost, for private
analysis.
