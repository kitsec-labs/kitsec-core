<p align="center">
  <img src="assets/logo.png" alt="seckit logo" width='50%' height='50%'/>
</p>


# Ethical hacking, made easy. 

Kitsec is a powerful toolkit CLI designed to help you simplify & centralize your security workflow. 
Whether you're a seasoned professional or just getting started, Kitsec provides a comprehensive set of tools to help you stay on top of your game.

### ✨ Features

- [**Convert**](#convert): Applies a specified decoding or hashing function to input data. (ie. URL, HTML, Base64, ASCII, Hex, Octal, Binary & GZIP).
- [**Enumerator**](#enumerator): Enumerates subdomains for a given domain using subfinder, amass, assetfinder and findomain and active enumeration.
- [**Capture**](#capture): Send a GET request to a specified URL, capture the request headers, extract the hostname, path, and cookies and missing headers.
- [**Portscan**](#portscan): Scan a host for common or all possible open ports.
- [**Certificate**](#certificate): Check the SSL/TLS certificate information for a given URL.
- [**Storm**](#storm): Sends HTTP requests to a given URL with a specified number of attacks and requests.
- [**Disturb**](#disturb): Send multiple HTTP requests to the specified URL with the same payload.
- [**Fuzz**](#fuzz): Test your web applications against path fuzzing and file fuzzing.
- [**CIDR**](#cidr): Looks up the CIDR range for a company's domain name from its RDAP record.
- [**CVE**](#cve): Retrieves CVE data for a specific product name (company name) from NIST's National Vulnerability Database (NVD).
- [**VPS**](#vps-logger): Login to your VPS with a single command.


### 🛣️ Roadmap

- **Storm**: Add raid types: flood, hybrid and single shot.
- **VPS**: Add linode logger.
- **Fuzz**: Enrich fuzzing.
- **Shuffler**: Enrich Shuffle IP/Agent/Referer lists.

### 📦 Installation 



<details>
  <summary>Install Docker</summary>

Install docker-compose and docker on your system:

````
$ sudo apt install docker-compose docker
```` 

or

````
$ brew install docker-compose docker
````

</details>

<details>
  <summary>Run using Docker </summary>


To build the docker image run:

````
docker build -t kitsec .
````

To run kitsec within the docker container:

````
docker run -it kitsec python kitsec/kitsec.py <command> <options>
````

</details>

<details>
  <summary>Run using Python </summary>

Install dependencies:
  
````
pip install -r requirements.txt
````


Install go dependencies:

````
python kitsec.py deps
````

Run kitsec:

````
python kitsec.py <command> <options>
````


</details>

<details>

  <summary>tips</summary>
  
``````
to ease the process, you can add an alias to your shell file:

````
# Add alias for Bash shell
echo "alias drk='docker run -it kitsec'" >> ~/.bashrc

# Add alias for Zsh shell
if [[ -n $(command -v zsh) ]]; then
    echo "alias drk='docker run -it kitsec'" >> ~/.zshrc
fi

# Add alias for Fish shell
if [[ -n $(command -v fish) ]]; then
    echo "alias drk 'docker run -it kitsec'" >> ~/.config/fish/config.fish
fi
``````
</details>

# Usage


### 📸 Capture <a name="capture"></a>

Intercept requests to example.com. This will capture the request headers and extract the hostname and path + cookies! :

``````
Usage: python kitsec.py capture [OPTIONS] URL

  Captures the request headers for a given URL.

Options:
  --help  Show this message and exit.

Example:
  python kitsec.py capture https://example.com
``````

<details>
  <summary>Output</summary>
  
``````
GET /mynetwork/ HTTP/1.1
Host: www.website.com
Accept-Encoding: gzip, deflate, br
Accept: */*
Connection: keep-alive
Cookie: bcookie="v=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"; 
lang=v=2&lang=en-us; 
li_gc=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx; 
lidc="b=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"; 
JSESSIONID=ajax:xxxxxxxxxxxxxxxxxx; 
bscookie="v=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

Response headers:
    Cache-Control: no-cache, no-store
    Pragma: no-cache
    Content-Length: 7486
    Content-Type: text/html; charset=utf-8
    Content-Encoding: gzip
    Expires: Thu, 01 Jan 1970 00:00:00 GMT
    Vary: Accept-Encoding
    Content-Security-Policy: default-src *; connect-src 'self' *.domain etc etc etc *
    X-Frame-Options: sameorigin
    X-Content-Type-Options: nosniff
    Strict-Transport-Security: max-age=31536000
    Expect-CT: max-age=86400, report-uri="https://www.website.com/platform-telemetry/ct"
    X-Li-Fabric: prod-lzx7
    X-Li-Pop: azd-prod-lzx7-x
    X-Li-Proto: http/1.1
    X-LI-UUID: AAX2TIh6unm3s+DezlC6rw==
    X-Cache: CONFIG_NOCACHE
    X-MSEdge-Ref: Ref A: BB20069DED8C4CF68A735496B4DAFD79 Ref B: PAR02EDGE0721 Ref C: 2023-03-07T10:04:11Z
    Date: Tue, 07 Mar 2023 10:04:11 GMT
``````
</details>


### 🪄 Convert <a name="convert"></a>

Convert your data from one format to another:

````
Usage: kitsec convert [OPTIONS] INPUT [-t TYPE]

Applies a specified decoding or hashing function to input data.

Arguments:
INPUT The input data to be converted.

Options:
-t, --type TYPE The type of conversion to apply (HTML, Base64, ASCII, 
Hex, Octal, Binary & GZIP).
--help Show this message and exit.

Example:
python kitsec.py convert S2l0c2VjIFJvY2tzIQ== -t Base64
````

<details>
  <summary>Output</summary>
  
  ```
  Kitsec Rocks!
  ```
</details>

 ### 🧮 Enumerate <a name="enumerate"></a>

Enumerate subdomains for example.com

````
Usage: python kitsec.py enumerate [OPTIONS] DOMAIN

Enumerates subdomains for a given domain using Subfinder and active enumeration.

Arguments:
DOMAIN The domain to enumerate subdomains for.

Options:
-r, --request Fetch HTTP response for active subdomains.
-t, --technology Analyze technologies used by subdomains.
-a, --active Perform active enumeration.
--help Show this message and exit.

Example:
python kitsec.py enumerate -r -t -a example.com 
````

<details>
  <summary>Output</summary>
  
```
Subdomain                       Status  Reason               Technology
----------------------------  --------  -------------------  ----------------------------------------------------------------
tracking.webapp.domain1.com        503  Service Unavailable  []
legal.domain1.com                  404  Not Found            ['Strikingly', 'Lua', 'jQuery', 'Nginx', 'OpenResty']
help.domain1.com                   403  Forbidden            ['Cloudflare']
staging-api.domain1.com            401  Unauthorized         []
api.domain1.com                    401  Unauthorized         []
staging-app.domain1.com            200  OK                   ['Nginx', 'Google Font API', 'React', 'Stripe']
staging-website.domain1.com        200  OK                   ['Nginx', 'Google Font API', 'React', 'Stripe']
sales.domain1.com                  200  OK                   ['Nginx', 'Google Font API', 'React', 'Stripe']
```

</details>

### 📡 Port Scan <a name="portscan"></a>

Scan for all or most common open ports on example.com:

````
Usage: kitsec.py portscan [OPTIONS] HOSTNAME

Performs a TCP port scan on a specified hostname and a range of ports.

Arguments:
HOSTNAME The hostname or URL of the target host.

Options:
-c, --common-ports Scan only the most common HTTP ports (80, 8080, and 443).
--help Show this message and exit.

Example:
python kitsec.py portscan -c example.com 
````

<details>
  <summary>Output</summary>
  
```
Open Ports:
example.com:80
example.com:443
```

</details>

### 📶 CIDR <a name="cidr"></a>

Search for CIDR ranges for a given domain name:

`````
Usage: python kitsec.py cidr [OPTIONS] COMPANY_NAME

Look up the CIDR range for a company's domain name.

Arguments:
  COMPANY_NAME  The name of the company's domain name to look up.

Options:
  --help           Show this message and exit.

Returns:
  - The CIDR range for the company's domain name as a string.
  - If an exception is raised during the lookup process, 
  an error message will be displayed.

Example:
  python kitsec.py cidr github.com
`````
<details>
  <summary>Output</summary>

`The CIDR range for domain.com is 141.82.112.0/20`
</details>

### 📜 Certificate <a name="certificate"></a>

Search for ssl / tlsfor the specified host and port:

`````
Usage: python kitsec.pycertifcate [OPTIONS] HOSTNAME

Check the SSL/TLS certificate for the specified host and port.

Arguments:
  HOSTNAME  The hostname to check the certificate for.

Options:
  -p, --port INTEGER  The port to connect to. Default is 443.
  --help              Show this message and exit.

Returns:
  None. Displays the certificate information to the console.

Example:
  python kitsec.py certificate github.com

`````
<details>
  <summary>Output</summary>

````
Hostname: github.com
Not Before: 2023-02-14 00:00:00
Not After: 2024-03-14 23:59:59
````
</details>

### 🌐 CVE <a name="cve"></a>

Search for CVEs for the specified product.

`````
Usage: python kitsec.py cve [OPTIONS] PRODUCT_NAME

Retrieves CVE data for a specific product and displays it.

Arguments:
  PRODUCT_NAME  The product name (company name) to search for.

Options:
  --limit INTEGER  Number of results to display (default=10).
  --help           Show this message and exit.

Example:
  python kitsec.py cve python -l 2
`````

<details>
  <summary>Output</summary>

```
CVE ID    CVE-2023-26477
CWE       CWE-94: Improper Control of Generation of Code ('Code Injection') (4.10)
Severity  Severity information not available
Summary   XWiki Platform is a generic wiki platform. Starting in versions 6.3-rc-1 and 6.2.4, it's possible to inject arbitrary wiki syntax including Groovy, Python and Velocity script macros via the `newThemeName` request parameter (URL parameter), in combination with additional parameters. This has been patched in the supported versions 13.10.10, 14.9-rc-1, and 14.4.6. As a workaround, it is possible to edit `FlamingoThemesCode.WebHomeSheet` and manually perform the changes from the patch fixing the issue.

CVE ID    CVE-2018-1000802
CWE       CWE-77: Improper Neutralization of Special Elements used in a Command ('Command Injection') (4.10)
Severity  Severity information not available
Summary   Python Software Foundation Python (CPython) version 2.7 contains a CWE-77: Improper Neutralization of Special Elements used in a Command ('Command Injection') vulnerability in shutil module (make_archive function) that can result in Denial of service, Information gain via injection of arbitrary files on the system or entire drive. This attack appear to be exploitable via Passage of unfiltered user input to the function. This vulnerability appears to have been fixed in after commit add531a1e55b0a739b0f42582f1c9747e5649ace.
```

</details>


### 🌪️ storm <a name="storm"></a>

Send HTTP requests to a given URL with a specified number of Attacks and requests.

`````
Usage: python kitsec.py storm [OPTIONS] URL

Sends HTTP requests to a given URL with a specified number of threats and requests.

Arguments:
URL The URL to send HTTP requests to.

Options:
-a, --num-attacks INT Number of parallel attacks to send requests from. Default: 6.
-r, --num-requests INT Number of requests to send from each threat. Default: 200.
-y, --num-retries INT Number of times to retry failed requests. Default: 4.
-p, --pause-before-retry INT Number of milliseconds to wait before retrying a failed 
request. Default: 3000.
--help Show this message and exit.

Example:
python kitsec.py storm https://example.com/
`````

### 🌫️ fuzz <a name="fuzz"></a>


`````
Usage: python kitsec.py fuzz [OPTIONS] BASE_URL

Sends HTTP GET requests to a specified base URL with a given list of paths.

Arguments:
BASE_URL The base URL to send requests to. The URL must include the protocol (http or https).

Options:
-p, --path PATH The path to a file or directory containing a list of paths to send requests 
to. Default: ../lists/fuzz/path_fuzz
-f, --file-fuzz Use file format fuzzing
--help Show this message and exit.

Example:
python kitsec.py fuzz example.com
`````

### 🧢 VPS <a name="vps-logger"></a>

Connects to a remote VPS server and tails the auth.log file.

``````
Usage: python kitsec.py vps-logger [OPTIONS]

Connects to a remote VPS server and tails the auth.log file.

Prompts:
  -h, --host TEXT      The IP address of the VPS server to connect to.
  -u, --username TEXT  The limited user account to use for connecting to the VPS server.
  -p, --password TEXT  The password for the user account.
  --help               Show this message and exit.

Returns:
- Prints a continuous stream of output from the auth.log file to the console.

The program attempts to connect to the specified VPS server using SSH, with the provided
username and password. Once connected, it invokes a shell and sends the command to tail
the auth.log file using sudo. It then continuously checks for new output from the file and
prints it to the console as it is received.
``````

# Guidelines

Here are some guidelines for using open source tools for ethical hacking:

<ol>
  <li>Bug bounties are not a license to hack indiscriminately. Stay within your scope and safe harbour.</li>

  <li>Ensure you have a strong understanding of the open source tools being used and their impact.</li>

  <li>Always obtain written permission from the owner of the target system before testing.</li>

  <li>Never go beyond the scope of the agreement.</li>

  <li>Be professional in your approach.</li>
</ol>

Here are some examples of websites that offer bug bounty programs for ethical hackers to test their skills:

<ol>

  <li><a href="https://bughunters.google.com/">Google Vulnerability Reward Program</a></li>
  
  <li><a href="https://www.microsoft.com/en-us/msrc/bounty">Microsoft Bounty Program</a></li>

  <li><a href="https://www.hackerone.com/">HackerOne</a></li>

  <li><a href="https://www.bugcrowd.com/">Bugcrowd</a></li>

  <li><a href="https://www.synack.com/">Synack</a></li>
</ol>


# Reporting Bugs and Contributing

If you encounter any bugs or would like to suggest new features [here](https://github.com/kitsec-labs/kitsec/issues/new)

# Disclaimer

This project is made for educational and ethical testing purposes only. Usage of this tool for attacking targets without prior mutual consent is illegal. Developers assume no liability and are not responsible for any misuse or damage caused by this tool.

# Acknowledgements

Thank you to @projectdiscovery, @milo2012, @duyet, @ayoubfathi, @Bo0oM and @Practical-Formal-Methods for opening their tools to the world.

# License

Kitsec is licensed under the [MIT License](https://github.com/kitsec-labs/kitsec-core/blob/main/LICENSE).
