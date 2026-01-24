FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# 1. Dépendances système
RUN apt-get update && apt-get install -y \
    curl \
    git \
    xz-utils \
    build-essential \
    llvm-14 \
    llvm-14-dev \
    clang-14 \
    lld-14 \
    mingw-w64 \
    ca-certificates \
    openssl \
    && rm -rf /var/lib/apt/lists/*

# 2. Installation de Nim via choosenim
RUN curl https://nim-lang.org/choosenim/init.sh -sSf | sh -s -- -y

# 3. Configuration du PATH
ENV PATH="/root/.nimble/bin:${PATH}"

# 4. Configuration SSL/TLS pour nimble (au cas où)
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt

# 5. Installation des packages avec retry
RUN nimble refresh -y || (sleep 5 && nimble refresh -y) && \
    nimble install -y winim || echo "winim installation échouée" && \
    nimble install -y puppy || echo "puppy installation échouée" && \
    nimble install -y ptr_math || echo "ptr_math installation échouée"

# 6. Liens symboliques LLVM
RUN ln -s /usr/bin/llvm-config-14 /usr/bin/llvm-config && \
    ln -s /usr/bin/llvm-link-14 /usr/bin/llvm-link && \
    ln -s /usr/bin/opt-14 /usr/bin/opt && \
    ln -s /usr/bin/clang-14 /usr/bin/clang && \
    ln -s /usr/bin/clang++-14 /usr/bin/clang++

WORKDIR /app

# 7. Préparation du script de build
COPY llvm/build_exe.sh /usr/local/bin/build_exe
RUN chmod +x /usr/local/bin/build_exe

# 8. Copie des passes LLVM
COPY llvm-pass /app/llvm-pass

ENTRYPOINT ["build_exe"]