# glibc binaries built on ubuntu-24.04 (see .github/workflows/erpis-release.yml);
# they need only libc/libm/libgcc_s, all present in the base image.
FROM ubuntu:24.04
COPY hbbs /usr/bin/hbbs
COPY hbbr /usr/bin/hbbr
WORKDIR /root
ENV HOME=/root
