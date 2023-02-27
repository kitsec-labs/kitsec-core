<p align="center">
  <img src="assets/logo.png" alt="seckit logo" width='50%' height='50%'/>
</p>

# Ethical hacking, made easy. 🪄

Kitsec is a powerful toolkit CLI designed to help you centralize your security workflow and take your cybersecurity skills to the next level. Whether you're a seasoned professional or just getting started, Kitsec provides a comprehensive set of tools to help you stay on top of your game.

Disclaimer: Use this tool ethically and legally as part of Bug Bounties or Security Audits. The author is not responsible for any misuse of this tool.

### Features

- **Linode**: Login to your linode VPS with a single command.
- **Enumerator**: A powerful subdomain enumeration tool to help you identify potential subdomains and the technology used by them [Includes subfinder, soon AMASS].
- **Raider**: A modular tool to help you test your web applications against intruding.
- **Port Scanner**: A tool to help you scan ports.
- **Injector**: A modular tool to help you test your web applications against SQL injection attacks

### Soon

- **Vulnerability Scanner**: A tool to help you scan for vulnerabilities.
- **Report Generator**: A tool to help you generate reports.
- **Slack Bot**: A tool to help you integrate Kitsec with Slack.

### Installation 

To install the dependencies, run the following commands:

```
brew install python3
brew install go
brew install amass
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```

To install Kitsec, simply clone the repository and run the following command to install the required dependencies:

```
pip install kitsec
```

To log into your linode vps (optional):

```
kitsec linode
```

# Usage

### Enumerator 🧮

Enumerate subdomains for example.com using [subfinder](https://github.com/projectdiscovery/subfinder):

`kitsec enumerator example.com`

Test subdomains for example.com and print http response:

`kitsec enumerator -r example.com`

Test subdomains for example.com and print http response and technology

`kitsec enumerator -t -r example.com`

This function tests against [leaky paths](https://github.com/ayoubfathi/leaky-paths) that are located in  lists/active_enumerator/.

### Port Scanner 📡

Scan ports for example.com:

`kitsec portscanner example.com`


### Raider 🥷

Tests a base url against a bruteforce threat:

`kitsec raider example.com`

Tests a base url against a DDOS threat with 10 parallel threats, 100 requests per threat, 8 retries, and 5 second pause before retry:

`kitsec raider example.com -t 10 -r 100 -n 8 -p 5000`

### Injector 💉

Tests a base URL against a curated list of [path](https://github.com/milo2012/pathbrute)  [sql, php, ASP.NET]:

`kitsec injector example.com`

To test a base URL with a list of paths in a file:

`kitsec injector https://example.com /path/to/lists`

You can update the list you want to inject in the directory lists/injector/.

# Guidelines

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

  <li>(HackerOne)[https://www.hackerone.com/] - A platform for businesses to connect with ethical hackers who can identify security vulnerabilities and report them.</li>

  <li>(Bugcrowd)[https://www.bugcrowd.com/] - A crowdsourced security testing platform that offers bug bounty programs to ethical hackers.</li>

  <li>(Synack)[https://www.synack.com/] - A platform that offers a crowdsourced model for testing security and identifying vulnerabilities.</li>

  <li>(Google Vulnerability Reward Program)[https://bughunters.google.com/] - A program that offers rewards to ethical hackers who can identify vulnerabilities in Google's products.</li>

  <li>(Microsoft Bounty Program)[https://www.microsoft.com/en-us/msrc/bounty] - A program that offers rewards to ethical hackers who can identify vulnerabilities in Microsoft's products.</li>

  <li>It's important to note that while bug bounty programs are legal, they are not a license to hack indiscriminately. Always follow ethical hacking guidelines and obtain permission before testing any systems, to ensure that your actions are legal and ethical.</li>
</ol>

# Reporting Bugs and Contributing

If you encounter any bugs or would like to suggest new features, please create an issue on the GitHub repository. Contributions are also welcome! If you would like to contribute to Kitsec, please create a pull request on the GitHub repository.

# Acknowledgements

Thank you to @projectdiscovery, @milo2012, @duyet & @ayoubfathi for opening their tools to the world.

# License

Seckit is licensed under the [MIT License](https://github.com/your-username/seckit/blob/main/LICENSE).
