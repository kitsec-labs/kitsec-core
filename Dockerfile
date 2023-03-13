FROM python:3.8-slim-buster

# Install necessary dependencies for Go installation
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        wget \
        tar \
        libmagic1 \
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

# Install required Go packages using go install
RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install github.com/OWASP/Amass/v3/...

# Set the working directory to /app and copy source code
WORKDIR /app
COPY requirements.txt .
RUN pip install --upgrade pip
RUN pip install -r requirements.txt
COPY src /app/src
COPY lists/fuzz/path_fuzz /app/lists/fuzz/path_fuzz

# Set the working directory to the parent directory of src and lists
WORKDIR /app
CMD ["python", "src/kitsec.py"]