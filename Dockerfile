# Developer sandbox Dockerfile lives at:
# developer/docker/Dockerfile
#
# The root Dockerfile intentionally delegates to the published sandbox image so
# accidental root builds behave like normal skill installs.

FROM ghcr.io/openghost/openghost-sandbox:latest
