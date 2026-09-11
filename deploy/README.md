# Deployment files

Start with the [deployment guide](../docs/deployment.md). It covers prerequisites,
building the images, a deployment plan, first startup, administrator bootstrap, and verification.
The next step is [first use of the Console](../docs/after-verify.md).

`dsse-install -plan <plan.json> -dir <deployment-directory> -order` prints the commands
for the selected machines. The installer generates `deployment.env`, certificates,
start scripts, and `docker-compose.yml`; run Compose from that generated directory.
Do not start Compose in this source directory.

| File | Purpose |
|---|---|
| [Dockerfile](Dockerfile) | Edge, control plane, connector, and operator tools |
| [Dockerfile.console](Dockerfile.console) | Admin Console server and static assets |

Build both images from the same revision using [Building](../docs/building.md).
A deployment runs `dsse-edge` in two roles: the control plane uses `-control-plane`,
and Edges enforce the configuration it distributes. Generated start scripts select the role.
