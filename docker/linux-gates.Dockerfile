# Runs the Linux-only private-routing gates on a non-Linux workstation.
#
# KI-2 keeps the eleven-role live scenarios out of the portable aggregate
# because macOS and Windows refuse the 127.64.x.1 role binds, and KI-3 keeps the
# namespace gates behind privileged Linux. Both hold on a Linux container, so
# this image exists to run those gates locally instead of only in CI.
#
# Dependencies install to /node_modules, not /app/node_modules: the runner
# bind-mounts the working tree at /app and shadows /app/node_modules with a
# tmpfs, so a host node_modules built for darwin can never be loaded here while
# Node resolution still falls through to the Linux build one directory up.

FROM node:22-bookworm-slim

# git: the dht-rpc dependency is a git reference.
# iproute2, iptables, tcpdump: the namespace gates provision veths and capture.
# sudo: the provisioner shells out through `sudo -n` even when already root.
# procps: the provisioner enables ip_forward through sysctl.
# python3/make/g++: fallback when a native dependency has no prebuild.
RUN apt-get update \
  && apt-get install -y --no-install-recommends \
    ca-certificates \
    g++ \
    git \
    iproute2 \
    iptables \
    make \
    procps \
    python3 \
    sudo \
    tcpdump \
  && rm -rf /var/lib/apt/lists/*

# The repository ignores package-lock.json, like upstream hyperdht and its CI, so
# this installs from package.json alone.
WORKDIR /deps
COPY package.json ./
# The bare-runtime platform package ships its binary mode 644, so the Bare gates
# cannot exec it as installed; the chmod below fixes that.
RUN npm install --no-audit --no-fund \
  && mv /deps/node_modules /node_modules \
  && rm -rf /deps /root/.npm \
  && find /node_modules -path '*bare-runtime-*/bin/bare' -exec chmod +x {} +

ENV PATH=/node_modules/.bin:$PATH
WORKDIR /app
