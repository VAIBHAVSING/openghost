# Maintainer sandbox Dockerfile lives at:
# docker/Dockerfile
#
# The root Dockerfile intentionally delegates to the published sandbox image so
# accidental root builds behave like normal skill installs.

FROM ghcr.io/vaibhavsing/openghost-sandbox:latest
