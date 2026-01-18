FROM nimlang/nim:2.0.0-alpine

# Install mingw-w64 for cross-compilation to Windows
RUN apk add --no-cache mingw-w64-gcc

# Create non-root user
RUN adduser -D -u 1000 -h /home/nimuser nimuser

# Create a workspace that is writable
WORKDIR /workspace
RUN chown nimuser:nimuser /workspace

USER nimuser
