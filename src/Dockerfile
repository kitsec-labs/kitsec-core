FROM python:3.9

# Install Go and other dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        golang \
    && rm -rf /var/lib/apt/lists/*

RUN go get -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go get github.com/tomnomnom/assetfinder@latest && \
    go get github.com/tomnomnom/waybackurls@latest && \
    go get -v github.com/OWASP/Amass/v3/...@master

# Copy the source code into the container
COPY src /app
WORKDIR /app

# Install Python dependencies
RUN pip install --upgrade pip
RUN pip install -r requirements.txt

# Run the application
CMD ["python", "kitsec.py"]