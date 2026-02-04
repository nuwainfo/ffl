FROM alpine:3.20

RUN apk add --no-cache ca-certificates curl && update-ca-certificates

# If "latest": use releases/latest/download/ffl.com
# Else: download from releases/download/<tag>/ffl.com (e.g. v3.8.2)
ARG FFL_RELEASE_TAG=latest

RUN set -eux; \
    if [ "$FFL_RELEASE_TAG" = "latest" ]; then \
      url="https://github.com/nuwainfo/ffl/releases/latest/download/ffl.com"; \
    else \
      url="https://github.com/nuwainfo/ffl/releases/download/${FFL_RELEASE_TAG}/ffl.com"; \
    fi; \
    curl -fL "$url" -o /usr/local/bin/ffl.com \
    && chmod +x /usr/local/bin/ffl.com \
    # Create a friendly wrapper name "ffl" with sh-fallback for some exec environments
    && printf '%s\n' \
      '#!/bin/sh' \
      'set -e' \
      'if /usr/local/bin/ffl.com --version >/dev/null 2>&1; then' \
      '  exec /usr/local/bin/ffl.com "$@"' \
      'else' \
      '  exec sh /usr/local/bin/ffl.com "$@"' \
      'fi' \
      > /usr/local/bin/ffl \
    && chmod +x /usr/local/bin/ffl

# (Optional) run as non-root; if you want NAS volume write access, you may need to tune uid/gid.
# RUN adduser -D -u 1000 ffl && chown -R ffl:ffl /usr/local/bin/ffl /usr/local/bin/ffl.com
# USER ffl

ENTRYPOINT ["ffl"]
CMD ["--help"]
WORKDIR /data
