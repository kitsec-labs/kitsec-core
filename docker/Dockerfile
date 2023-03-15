FROM python:3.9-slim

# Install necessary dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        wget \
        tar \
        libmagic1 \
        gcc \
        && rm -rf /var/lib/apt/lists/*

# Download and extract Go 1.19 binary archive
RUN wget https://go.dev/dl/go1.19.linux-amd64.tar.gz && \
    tar -xvf go1.19.linux-amd64.tar.gz && \
    mv go /usr/local && \
    rm go1.19.linux-amd64.tar.gz

# Set Go environment variables
ENV GOROOT=/usr/local/go
ENV GOPATH=/go
ENV PATH=$GOPATH/bin:$GOROOT/bin:$PATH

# Set the working directory to /app
WORKDIR /app

# Upgrade pip and install the kitsec package from TestPyPI
RUN pip install --upgrade pip
RUN pip install kitsec==0.1.6rc3

# Set the working directory to the parent directory of core
WORKDIR /app
ENV PYTHONPATH=/app

# Set the default command to run the kitsec CLI
CMD ["kitsec"]