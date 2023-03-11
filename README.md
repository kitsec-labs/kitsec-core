<p align="center">
  <img src="assets/logo.png" alt="seckit logo" width='50%' height='50%'/>
</p>

# Ethical hacking, made easy. 

Kitsec is a powerful toolkit CLI designed to help you smplify & centralize your security workflow. 
Whether you're a seasoned professional or just getting started, Kitsec provides a comprehensive set of tools to help you stay on top of your game.

### ✨ Features

- **VPS Logger**: Login to your VPS with a single command.
- **Collab**: A collaborative terminal that allows you to share your terminal with your team-mate using a VPS.
- **Capture**: A tool to send a GET request to a given URL and capture the request headersand extract the hostname and path + cookies!
- **Convert**: A tool that automatically detects various formats and convert them (ie. URL, HTML, Base64, ASCII, Hex, Octal, Binary & GZIP).
- **Disturb**: This tool sends multiple requests to a web server with the same payload, in order to test for vulnerabilities or analyze server behavior.
- **Enumerator**: A powerful active and passive subdomain enumeration tool that scrapes technology using subfinder, amass, assetfinder and findomain.
- **Raid**: A modular tool to help you test your web applications.
- **Portscan**: A tool to help you scan ports.
- **Inject**: A modular tool to help you test your web applications against SQL injection attacks.
- **cve**: A tool that queries the CVE data for a specific product name (company name) from NIST's National Vulnerability Database (NVD) and returns it in a table format with columns for CVE ID, CWE, severity, and summary.
- **fuzz**: A tool to help you fuzz for vulnerabilities.


### 🛣️ Roadmap

- **Add raid types**: Add flood, hybrid and single shot
- **Fuzz**: A tool to help you fuzz for vulnerabilities.
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


### To install subfinder using go install:

Make sure you have Go installed and properly configured.

Run the following command in your terminal:

`go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest`
`go install github.com/tomnomnom/assetfinder@latest`
`pip install Sublist3r`
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

### To install subfinder using go install:

Make sure you have Go installed and properly configured.

Run the following command in your terminal:

`go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest`

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

### To install subfinder using go install:

Make sure you have Go installed and properly configured.

Run the following command in your terminal:

`go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest`

Make sure you set it up correctly (i.e. APIs keys). More infos [here](https://github.com/projectdiscovery/subfinder)

</details>


# Usage

### 🧢 Capture

Intercept requests to example.com. This will capture the request headers and extract the hostname and path + cookies! :

`kitsec capture`

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



### 🪄 convert:

Convert your data from one format to another:

`kitsec convert`

 ### 🧮 Enumerate

Enumerate subdomains for example.com (requires [subfinder](https://github.com/projectdiscovery/subfinder)):

`kitsec enumerate`

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




### 🥷 Raid 

Tests a base url against a bruteforce threat:

`kitsec raid`


### 📡 Port Scan

Scan ports :

`kitsec portscan`

### 💉 Inject

Tests a base URL against a curated list of [path](https://github.com/milo2012/pathbrute)  [sql, php, ASP.NET]:

`kitsec inject`

### 🌫️ Fuzz

Fuzz a base URL with a curated list of path

### 🌐 CVE

Search for vulnerabilities in the NVD database [0 = No limit]:

`kitsec cve`

# 🚨 Guidelines

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


# 💡 Reporting Bugs and Contributing

If you encounter any bugs or would like to suggest new features, please create an issue on the GitHub repository. Contributions are also welcome! If you would like to contribute to Kitsec, please create a pull request on the GitHub repository.

# 🙏🏽 Acknowledgements

Thank you to @projectdiscovery, @milo2012, @duyet & @ayoubfathi for opening their tools to the world.

# 🔖  License

Kitsec is licensed under the [MIT License](https://github.com/your-username/seckit/blob/main/LICENSE).
