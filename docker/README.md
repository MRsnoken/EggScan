# Docker

Docker is an alternative to the system installer. Both use the same EggScan
application, features and database format. Only process management, data paths
and the update instructions on the About page differ. Do not run the system
installer inside a container.

## Requirements

- Linux with Docker Engine and Docker Compose v2.
- AMD64 or ARM64 hardware.
- Direct access to the LAN you want to monitor.

Host networking is required for ARP discovery and access to IPv6 neighbors.
Docker Desktop on macOS/Windows and rootless Docker are not supported by this
configuration.

## Start

From the repository root:

```bash
docker compose -f docker/compose.yaml up -d
```

Open http://localhost:5000 on the host, or http://<server-ip>:5000 from another
device. Create an admin account and select your networks in Settings.

The web interface listens on all IPv4 interfaces by default. Use a trusted
private network; protect initial account setup from other users. Do not expose
EggScan directly to the public internet.

## Settings

Defaults work without an environment file. To override them:

```bash
cp docker/.env.example docker/local.env
docker compose --env-file docker/local.env -f docker/compose.yaml up -d
```

| Setting | Default |
| --- | --- |
| `EGGSCAN_WEB_HOST` | `0.0.0.0` — localhost and LAN access |
| `EGGSCAN_WEB_PORT` | `5000` |
| `EGGSCAN_IMAGE` | `ghcr.io/mrsnoken/eggscan:latest` |

Use the same environment file for later commands. Personal environment files
are excluded from Git and the image build. Host networking does not use Docker
port mappings; change `EGGSCAN_WEB_PORT` to select a different port.

For HTTPS, use an existing reverse proxy. Binding to `127.0.0.1` limits direct
HTTP access to the host when the proxy also runs there. A proxy on another host
needs a reachable address and appropriate access restrictions.

## Data and updates

Both services share the named volume `eggscan-data`, mounted at `/data`.
With the default project name, Docker calls it `eggscan_eggscan-data`.
It stores the database, settings, users and session key. Keep the same Compose
project name and volume when replacing containers.

Do not mount a running native installation's data directory into these
containers. Each installation must have its own database.

To update a published image:

```bash
docker compose -f docker/compose.yaml pull
docker compose -f docker/compose.yaml up -d
```

The system web updater is disabled in Docker. Back up before upgrading; an older
image may not support a database upgraded by a newer version.

`docker compose -f docker/compose.yaml down` retains the data volume.
**Adding `-v` deletes it.**

## Backup

Settings provides a database backup download. It does not include the session
key. For a full volume backup, stop both services first:

```bash
docker compose -f docker/compose.yaml stop
(umask 077; docker compose -f docker/compose.yaml run --rm --no-deps -T --entrypoint tar web -C /data -czf - . > eggscan-data.tar.gz)
docker compose -f docker/compose.yaml start
```

Keep backups private: they contain settings, credentials and the session key.

## Build from source

```bash
docker build --pull --no-cache -f docker/Dockerfile -t eggscan:local .
EGGSCAN_IMAGE=eggscan:local docker compose -f docker/compose.yaml up -d
```

For subsequent commands, retain `EGGSCAN_IMAGE=eggscan:local` or put it in your
local environment file. Updates to a local image require rebuilding it before
recreating the containers.

The same Dockerfile supports `linux/amd64` and `linux/arm64`. A multi-platform
image lets Docker select the correct architecture automatically. Python
dependencies are pinned in `docker/requirements.lock` and installed together
with the application's `requirements.txt`. Conflicting versions fail the
build. The Python 3.11 / Debian 13 base image is pinned by digest. Refresh and
test these dependencies before releases.

## Release builds

The Docker workflow validates builds on AMD64 and ARM64 without publishing on
pushes, pull requests or ordinary manual runs. Publishing a GitHub release
validates both architectures, then publishes those exact image archives as
`ghcr.io/mrsnoken/eggscan:<version>` without rebuilding after validation. Docker
selects the correct architecture automatically. Stable releases also update
`latest` only when they match GitHub's latest stable release; prereleases do not.
The release tag must match `v<version>` from `version.json`. Each publication also
provides a distinct `<version>-build.<run-id>.<attempt>` tag.

The workflow uses the repository's `GITHUB_TOKEN` with package write permission;
no Docker Hub account or separate registry password is needed. After the first
publication, set the package visibility to public in GitHub Packages so users
can pull it without signing in. Existing release tags must not be moved to add
Docker files; publish from a new release containing them.

## Security maintenance

Image builds refresh the Debian package index and apply available package
updates from the configured Debian 13 repositories. CI builds do not reuse
cached package layers. This does not install fixes available only upstream or
in another Debian release, and does not guarantee a vulnerability-free image.

Dependabot proposes base-image digest updates on weekdays and GitHub Actions
updates weekly. Review and merge these updates after validation; Python major
and minor upgrades are excluded. Python dependency pins in
`docker/requirements.lock` also need review when security fixes are released.

After the first Docker release, maintainers can select **Publish a security
rebuild** in the Docker workflow's manual run dialog. This requires the app
version and application files to match the latest stable release; packaging
and dependency updates may differ. It rebuilds both architectures without
requiring a new EggScan application version. Only the validated images are
published. Users apply it with the same
`pull` and `up -d` commands as other image updates. Data remains in the volume.

## Troubleshooting

```bash
docker compose -f docker/compose.yaml ps
docker compose -f docker/compose.yaml logs --tail 100 web scan
```

Check that the web port is free and that the host can reach the selected networks.
ARP discovery does not cross routers. IPv6 discovery uses observed neighbors,
not an exhaustive IPv6 scan.

Containers run as a non-root user with a read-only application filesystem.
Only `NET_RAW` is allowed for Nmap and ping; their file capabilities provide
that permission when needed. No privileged mode, Docker socket, host root
filesystem or systemd access is required.
