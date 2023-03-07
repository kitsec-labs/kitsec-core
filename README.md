<p align="center">
  <img src="assets/logo.png" alt="seckit logo" width='50%' height='50%'/>
</p>

# Ethical hacking, made easy. 

Kitsec is a powerful toolkit CLI designed to help you smplify & centralize your security workflow. 
Whether you're a seasoned professional or just getting started, Kitsec provides a comprehensive set of tools to help you stay on top of your game.

### ✨ Features

- **VPS Logger**: Login to your VPS with a single command.
- **Collab**: A collaborative terminal that allows you to share your terminal with your team.
- **Capture**: A tool to send a GET request to a given URL and capture the request headersand extract the hostname and path + cookies!
- **Decode**: A tool that automatically detects various formats and transforms (ie. URL, HTML, Base64, ASCII, Hex, Octal, Binary, and GZIP).
- **Inject**: A modular tool to help you test your web applications against SQL injection attacks.
- **Enumerate**: A powerful subdomain active and passive enumeration tool that scrapes.
- **Raid**: A modular tool to help you test your web applications against intruding.
- **Portscan**: A tool to help you scan ports.

### 🛣️ Roadmap

- **Fuzz**: A tool to help you fuzz for vulnerabilities.
- **XSS Scan**: Add XSS scanner.

### 📦 Installation 

To install the dependencies, run the following commands:

```
brew install python3
brew install go
brew install tmux
brew install amass
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```

To install Kitsec, simply clone the repository and run the following command to install the required dependencies:

```
pip install kitsec
```

To log into your vps  (optional):

```
kitsec vps_logger
```

# Usage

### 🧮 Enumerate

Enumerate subdomains for example.com using [subfinder](https://github.com/projectdiscovery/subfinder):

`kitsec enumerate example.com`

Output:

```
Subdomain                    
----------------------------   
tracking.webapp.domain1.com 
legal.domain1.com            
help.domain1.com             
staging-api.domain1.com       
api.domain1.com                
staging-app.domain1.com        
staging-website.domain1.com        
sales.domain1.com   
```            

Test subdomains for example.com and print http response:

`kitsec enumerate -r example.com`

Output:

```
Subdomain                       Status  
----------------------------  --------  
tracking.webapp.domain1.com        503 
legal.domain1.com                  404 
help.domain1.com                   403  
staging-api.domain1.com            401  
api.domain1.com                    401 
staging-app.domain1.com            200  
staging-website.domain1.com        200  
sales.domain1.com                  200  
```

Test subdomains for example.com and print http response and technology

`kitsec enumerate -t -r example.com`

Output:

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

Test subdomains for example.com and print http response and technology with active enumeration:

`kitsec enumerate -t -r -a example.com`

### 🥷 Raid 

Tests a base url against a bruteforce threat:

`kitsec raid example.com`

Tests a base url against a DDOS threat with 10 parallel threats, 100 requests per threat, 8 retries, and 5 second pause before retry:

`kitsec raid example.com -t 10 -r 100 -n 8 -p 5000`


### 💉 Inject

Tests a base URL against a curated list of [path](https://github.com/milo2012/pathbrute)  [sql, php, ASP.NET]:

`kitsec inject example.com`

You can update the list you want to inject in the directory lists/injector/.

### 📡 Port Scan

Scan ports for example.com:

`kitsec portscan example.com`

Scan top 3 ports for example.com:

`kitsec portscan -c example.com`

### 🧢 Capture

Intercept requests to example.com and modify the response by right clicking on the button, and saving link as. then pasting it in the CLI.:

`kitsec capture example.com/path`

```
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
```

### 🪄 Transformer:

Transforms your data from one format to another:

`kitsec decode  S2l0c2VjIFJvY2tzIQ== --type Base64`

```
Kitsec Rocks!
 ```
 
# 🚨 Guidelines

Open source tools for ethical hacking are a great way for security professionals and enthusiasts to test the security of their own systems, as well as those of others, in a legal and ethical manner. 
Here are some guidelines for using open source tools for ethical hacking:

<ol>
  <li>Always obtain written permission from the owner of the target system before performing any security testing or vulnerability scanning. This can include website owners, system administrators, and software developers.</li>

  <li>Keep all testing within the bounds of the permission granted. Don't go beyond the scope of the agreement and avoid harming the system, data, and users.</li>

  <li>Ensure you have a strong understanding of the open source tools being used and the potential impact of their use. This includes knowledge of common vulnerabilities and attacks, as well as the best practices for mitigating them.</li>

  <li>Use the open source tools in a controlled environment, with isolated testing environments and measures in place to prevent any damage to live systems or data.</li>

  <li>Be professional in your approach and avoid using tools to exploit vulnerabilities without clear intentions of reporting them to the owner.</li>
</ol>

Here are some examples of websites that offer bug bounty programs for ethical hackers to test their skills:

<ol>

  <li><a href="https://bughunters.google.com/">Google Vulnerability Reward Program</a> - A program that offers rewards to ethical hackers who can identify vulnerabilities in Google's products.</li>
  
  <li><a href="https://www.microsoft.com/en-us/msrc/bounty">Microsoft Bounty Program</a> - A program that offers rewards to ethical hackers who can identify vulnerabilities in Microsoft's products.</li>

  <li><a href="https://www.hackerone.com/">HackerOne</a> - A platform for businesses to connect with ethical hackers who can identify security vulnerabilities and report them.</li>

  <li><a href="https://www.bugcrowd.com/">Bugcrowd</a> - A crowdsourced security testing platform that offers bug bounty programs to ethical hackers.</li>

  <li><a href="https://www.synack.com/">Synack</a> - A platform that offers a crowdsourced model for testing security and identifying vulnerabilities.</li>

  <li>It's important to note that while bug bounty programs are legal, they are not a license to hack indiscriminately. Always follow ethical hacking guidelines and obtain permission before testing any systems, to ensure that your actions are legal and ethical. In other words: Stay withing your scope and safe harbour</li>
</ol>


# 💡 Reporting Bugs and Contributing

If you encounter any bugs or would like to suggest new features, please create an issue on the GitHub repository. Contributions are also welcome! If you would like to contribute to Kitsec, please create a pull request on the GitHub repository.

# 🙏🏽 Acknowledgements

Thank you to @projectdiscovery, @milo2012, @duyet & @ayoubfathi for opening their tools to the world.

# 🔖  License

Kitsec is licensed under the [MIT License](https://github.com/your-username/seckit/blob/main/LICENSE).
