# glibc binaries built on ubuntu-24.04 (see .github/workflows/erpis-release.yml);
# they need only libc/libm/libgcc_s, all present in the base image.
FROM ubuntu:24.04
# Current Ubuntu security fixes at build time; "İmajı tazele" in ErpisRustDeskAdmin
# rebuilds with --pull --no-cache so a refresh picks up new ones.
RUN apt-get update && apt-get -y upgrade && rm -rf /var/lib/apt/lists/*
COPY hbbs /usr/bin/hbbs
COPY hbbr /usr/bin/hbbr
WORKDIR /root
ENV HOME=/root
