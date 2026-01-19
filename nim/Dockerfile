FROM nimlang/nim:2.0.0-alpine

# Fix specific to some Alpine environments where apk lock persists
RUN rm -f /lib/apk/db/lock && apk update && apk add --no-cache mingw-w64-gcc

# Create non-root user
RUN adduser -D -u 1000 -h /home/nimuser nimuser

# Create a workspace that is writable
WORKDIR /workspace
RUN chown nimuser:nimuser /workspace

USER nimuser

# Install puppy for HTTP requests and winim for Windows API
RUN nimble update && nimble install -y puppy winim
