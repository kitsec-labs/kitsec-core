import subprocess


def install_dependencies():
    subprocess.run(['go', 'install', '-v', 'github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest'])
    subprocess.run(['go', 'install', 'github.com/tomnomnom/assetfinder@latest'])
    subprocess.run(['go', 'install', 'github.com/tomnomnom/waybackurls@latest'])
    subprocess.run(['go', 'install', '-v', 'github.com/OWASP/Amass/v3/...@master'])