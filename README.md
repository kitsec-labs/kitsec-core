<p align="center">
  <img src="assets/logo.png" alt="seckit logo" width='50%' height='50%'/>
</p>

# Ethical hacking, made easy. 🪄

Kitsec is a powerful toolkit CLI designed to help you streamline your security workflow and take your cybersecurity skills to the next level. Whether you're a seasoned professional or just getting started, Kitsec provides a comprehensive set of tools to help you stay on top of your game.

## Features

- **VPS login**: Login to your linode VPS with a single command.
- **Subdomain Enumeration**: A powerful subdomain enumeration tool to help you identify potential targets [Includes subfinder, soon AMASS].
- **Threat Testing**: A tool to help you test your web applications against intruding.
- **SQL Injection Testing**: A tool to help you test your web applications against SQL injection attacks
- **Vulnerability Scanning Tools**: A comprehensive suite of vulnerability scanning tools to help you identify and prioritize potential threats.
- **Reporting and Documentation Tools**: Built-in reporting and documentation tools to help you quickly and accurately report security issues and maintain audit trails.

## Installation


To install the dependencies, run the following commands:

```
brew install python3
brew install go
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

## Usage

### Enumerator 🧮

Enumerate subdomains for example.com using [subfinder](https://github.com/projectdiscovery/subfinder):

`kitsec enumerator example.com`

Test subdomains for example.com and print http response:

`kitsec enumerator -r example.com`

Test subdomains for example.com and print http response and technology

`kitsec enumerator -t -r example.com`

This function tests against [leaky paths](https://github.com/ayoubfathi/leaky-paths) that are located in  `lists/active_enumerator/`

### Intruder 🥷

Tests a base url against a bruteforce threat:

`kitsec intruder example.com`

Tests a base url against a DDOS threat with 10 parallel threats, 100 requests per threat, 8 retries, and 5 second pause before retry:

`kitsec intruder example.com -t 10 -r 100 -n 8 -p 5000`

### Injector 💉

Tests a base URL against a curated list of [path](https://github.com/milo2012/pathbrute)  [sql, php, ASP.NET]:

`kitsec injector example.com`

To test a base URL with a list of paths in a file:

`kitsec injector https://example.com /path/to/lists`

You can update the list you want to inject in the directory `lists/injector/`

## Reporting Bugs and Contributing

If you encounter any bugs or would like to suggest new features, please create an issue on the GitHub repository. Contributions are also welcome! If you would like to contribute to Seckit, please create a pull request on the GitHub repository.

## Acknowledgements

Thank you to @projectdiscovery, @milo2012, @duyet & @ayoubfathi for opening their tools to the world.

## License

Seckit is licensed under the [MIT License](https://github.com/your-username/seckit/blob/main/LICENSE).
