FROM alpine:3.11

# Install necessary dependencies for Go installation
RUN apk update && \
    apk add --no-cache ca-certificates wget tar && \
    wget https://go.dev/dl/go1.19.7.linux-amd64.tar.gz && \
    tar -xvf go1.19.7.linux-amd64.tar.gz && \
    mv go /usr/local && \
    rm go1.19.7.linux-amd64.tar.gz

# Set Go environment variables
ENV GOROOT /usr/local/go
ENV GOPATH /go
ENV PATH $GOPATH/bin:$GOROOT/bin:$PATH

RUN apk add --no-cache git go musl-dev && \
    unset GOPATH && \
    go get github.com/projectdiscovery/subfinder/v2/cmd/subfinder && \
    go get github.com/tomnomnom/assetfinder@v0.1.0 && \
    go get github.com/tomnomnom/waybackurls@v0.0.17 && \
    go get github.com/OWASP/Amass/v3@v3.16.6 && \
    go get github.com/nwaples/rardecode/v2

# Install Python 3.7.8 and pip
RUN apk add --no-cache python3=3.7.8-r1 && \
    python3 -m ensurepip && \
    rm -r /usr/lib/python*/ensurepip && \
    pip3 install --no-cache --upgrade pip setuptools wheel && \
    pip install pandas numpy --no-cache-dir

# Copy the source code and requirements.txt into the container
COPY requirements.txt /app/
COPY src /app/src
COPY lists /app/lists
WORKDIR /app

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Run the application
CMD ["python", "src/kitsec.py"]