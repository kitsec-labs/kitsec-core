<p align="center">
  <img src="assets/logo.png" alt="seckit logo" width='50%' height='50%'/>
</p>


# Ethical hacking, made easy. 

Kitsec is a powerful toolkit CLI designed to help you smplify & centralize your security workflow. 
Whether you're a seasoned professional or just getting started, Kitsec provides a comprehensive set of tools to help you stay on top of your game.

### ✨ Features

- [**VPS Logger**](#vps-logger): Login to your VPS with a single command.
- [**Capture**](#capture): Send a GET request to a specified URL, capture the request headers, and extract the hostname, path, and cookies.
- [**Convert**](#convert): Applies a specified decoding or hashing function to input data. (ie. URL, HTML, Base64, ASCII, Hex, Octal, Binary & GZIP).
- [**Enumerator**](#enumerator): Enumerates subdomains for a given domain using subfinder, amass, assetfinder and findomain and active enumeration.
- [**Portscan**](#portscan): Scan a host for common or all possible open ports.
- [**Certificate**](#certificate): Check the SSL/TLS certificate information for a given URL.
- [**Raid**](#raid): Sends HTTP requests to a given URL with a specified number of attacks and requests.
- [**Disturb**](#disturb): Send multiple HTTP requests to the specified URL with the same payload.
- [**Fuzz**](#fuzz): Test your web applications against path fuzzing and file fuzzing.
- [**CIDR**](#cidr): Looks up the CIDR range for a company's domain name from its RDAP record.
- [**CVE**](#cve): Retrieves CVE data for a specific product name (company name) from NIST's National Vulnerability Database (NVD).


### 🛣️ Roadmap

- **Add raid types**: Add flood, hybrid and single shot
- **XSS Scan**: Add XSS scanner.

### 📦 Installation 

To install the dependencies, run the following commands for:

<details>
  <summary>Apple</summary>

### To install Python 3 using Homebrew:

Run the following command in your terminal:

`brew install python3`


### To install Go using Homebrew:

Run the following command in your terminal:

`brew install go`


### To install go dependencies using go install:

Make sure you have Go installed and properly configured.

Run the following command in your terminal:

`go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest`


`go install github.com/tomnomnom/assetfinder@latest`


`go install github.com/tomnomnom/waybackurls@latest`


`brew install findomain`

Make sure you set it up correctly (i.e. APIs keys). More infos [here](https://github.com/projectdiscovery/subfinder)

</details>

<details>
  <summary>Linux</summary>
  
### To install Python 3:

Debian/Ubuntu: `sudo apt-get install python3`  
Fedora/RHEL: `sudo dnf install python3`  
CentOS: `sudo yum install python3`  

### To install Go:

Debian/Ubuntu: `sudo apt-get install golang`  
Fedora/RHEL/CentOS: `sudo dnf install golang`  

### To install go dependencings using go install:

Make sure you have Go installed and properly configured.

Run the following command in your terminal:

`go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest`


`go install github.com/tomnomnom/assetfinder@latest`


`go install github.com/tomnomnom/waybackurls@latest`

Make sure you set it up correctly (i.e. APIs keys). More infos [here](https://github.com/projectdiscovery/subfinder)

</details>


<details>
  <summary>Microsoft</summary>
  
### To install Python 3:  

Download the latest Python 3 installer from the official website: https://www.python.org/downloads/windows/  
Run the installer and follow the instructions to complete the installation.  

### To install Go:  

Download the latest Go installer from the official website: https://golang.org/dl/  
Run the installer and follow the instructions to complete the installation.  

### To install go dependencings using go install:

Make sure you have Go installed and properly configured.

Run the following command in your terminal:

`go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest`


`go install github.com/tomnomnom/assetfinder@latest`


`go install github.com/tomnomnom/waybackurls@latest`

Make sure you set it up correctly (i.e. APIs keys). More infos [here](https://github.com/projectdiscovery/subfinder)

</details>


# Usage

### 📶 VPS Logger <a name="vps-logger"></a>

Connects to a remote VPS server and tails the auth.log file.

`kitsec vps-logger -h <IP ADDRESS> -u <USERNAME> -p <PASSWORD>`

``````
"""
  Connects to a remote VPS server and tails the auth.log file.

  Returns:
  - Prints a string containing the captured request headers, including method, 
  hostname, path, cookies, and all other headers sent with the request.
"""
``````

### 📸 Capture <a name="capture"></a>

Intercept requests to example.com. This will capture the request headers and extract the hostname and path + cookies! :

`kitsec capture <url>`

``````
"""
  Captures the request headers for a given URL.

  Returns:
  - Prints a string containing the captured request headers, including method, 
  hostname, path, cookies, and all other headers sent with the request.
"""
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

`kitsec convert S2l0c2VjIFJvY2tzIQ== -t Base64`

````
"""
  Applies a specified decoding or hashing function to input data.

  Args:
  - data (bytes): The input data to be transformed.
  - transformation_type (str): The type of transformation to apply.

  Returns:
  - If the input data is text, the transformed input data as a string.
  - If the input data is binary, the resulting hash as a string.
  - If an invalid transformation type is specified, an error message as a string.
"""
````

<details>
  <summary>Output</summary>
  
  ```
  Kitsec Rocks!
  ```
</details>

 ### 🧮 Enumerate <a name="enumerate"></a>

Enumerate subdomains for example.com :

`kitsec enumerate -r -t -a domain.com`

````
"""
  Enumerates subdomains for a given domain using Subfinder and active enumeration.

  Args:
  - request : A flag indicating whether to fetch HTTP response for active subdomains.
  - technology : A flag indicating whether to analyze technologies used by subdomains.
  - active : A flag indicating whether to perform active enumeration.
  - domain : The domain to enumerate subdomains for.

  Returns:
  - If only subdomains are requested, returns a list of subdomains.
  - If only technology analysis is requested, returns a table containing:  subdomains 
  & technologies.
  - If only HTTP response is requested, returns a table containing: subdomains, 
  HTTP status & reason.
  - If both technology & HTTP response are requested, returns a table containing 
  the subdomains & HTTP status, reason, and technologies.
  - If an error occurs during enumeration or analysis, returns None.
"""
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

Scan for most common ports:

`kitsec portscan -c domain.com`

````
"""
  Performs a TCP port scan on a specified hostname or URL and a range of ports.

  Args:
  - url (str): The hostname or URL of the target host.

  Options:
  - common-ports (bool): Whether to scan only the most common HTTP ports (80, 8080, and 443).

  Returns:
  - A list of open ports found on the target host.
"""
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

Search for CIDR ranges.:

`kitsec cidr domain.com`

`````
"""
  Look up the CIDR range for a company's domain name.

  Args:
  - company_name (str): The name of the company's domain name to look up.

  Returns:
  - The CIDR range for the company's domain name as a string.
  - If an exception is raised an error message will be returned.
"""
`````
<details>
  <summary>Output</summary>

`The CIDR range for domain.com is 141.82.112.0/20`
</details>

### 📜 Certificate <a name="certificate"></a>

Search for CIDR ranges.:

`kitsec certificate domain.com`

`````
"""
  Check the SSL/TLS certificate for the specified host and port.

  Args:
  - hostname (str): The hostname to check the certificate for.
  - port (int): The port to connect to. Default is 443.

  Returns:
  - None

"""
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

Search for 5 vulnerabilities in the NVD database [0 = No limit]:

`kitsec cve python -l 2`

`````
"""
  Retrieves CVE data for a specific product and displays it.

  Args:
    - product_name (str): The product name (company name) to search for.

  Options:
    limit (int): Number of results to display (default=10).

  Returns:
    - str: A plain string with each CVE record.
"""
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


### 🥷 Raid <a name="raid"></a>


`kitsec raid domain.com`

`````
"""
Sends HTTP GET requests to the specified URL with a specified number of attacks 
and requests.

Args:
- url (str): The URL to send GET requests to.
- num_attacks (int): The number of attacks to execute.
- num_requests (int): The number of requests to send in each attack.
- num_retries (int): The number of times to retry failed requests.
- pause_before_retry (int): The number of milliseconds to pause before retrying 
failed requests.

Returns:
- A list of response objects for each attack.
"""
`````

### 🌫️ fuzz <a name="fuzz"></a>

`kitsec fuzz domain.com`

`````
"""
Sends HTTP GET requests to a specified base URL with a given list of paths.

  Args:
  - base_url (str): The base URL to send requests to.

  Options:
  - path (str): The path to a file or directory. Default: ../lists/injector

  Returns:
  - For each request sent, the program will print the URL and response code if it's 200.
"""
`````

# Guidelines

Here are some guidelines for using open source tools for ethical hacking:

<ol>
  <li>Bug bounties are not a license to hack indiscriminately. Stay withing your scope and safe harbour.</li>

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

If you encounter any bugs or would like to suggest new features https://github.com/kitsec-labs/kitsec/issues/new

# Disclaimer

This project is made for educational and ethical testing purposes only. Usage of this tool for attacking targets without prior mutual consent is illegal. Developers assume no liability and are not responsible for any misuse or damage caused by this tool.

# Acknowledgements

Thank you to @projectdiscovery, @milo2012, @duyet, @ayoubfathi, @Bo0oM and @Practical-Formal-Methods for opening their tools to the world.

# License

Kitsec is licensed under the [MIT License](https://github.com/kitsec-labs/kitsec-core/blob/main/LICENSE).
