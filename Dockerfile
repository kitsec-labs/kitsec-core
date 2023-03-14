FROM ubuntu:20.04

# Install necessary dependencies for Go installation and Python
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        wget \
        tar \
        libmagic1 \
        python3 \
        python3-pip \
        gcc \
        && rm -rf /var/lib/apt/lists/*

# Download and extract Go 1.19 binary archive
RUN wget https://go.dev/dl/go1.19.linux-amd64.tar.gz && \
    tar -xvf go1.19.linux-amd64.tar.gz && \
    mv go /usr/local && \
    rm go1.19.linux-amd64.tar.gz

# Set Go environment variables
ENV GOROOT /usr/local/go
ENV GOPATH /go
ENV PATH $GOPATH/bin:$GOROOT/bin:$PATH

# Set the working directory to /app and copy source code and lists
WORKDIR /app
COPY requirements.txt .
RUN pip3 install --upgrade pip
RUN pip3 install -r requirements.txt
COPY core /app/core
RUN pip3 install -e /app/core

# Set the working directory to the parent directory of core
WORKDIR /app
RUN ln -s /usr/bin/python3 /usr/bin/python
ENV PYTHONPATH=/app

# Set the default command to run the Python script
CMD ["python", "core/kitsec/cli/main.py"]