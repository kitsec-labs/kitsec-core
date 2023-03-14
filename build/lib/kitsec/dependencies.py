import subprocess

def install_dependencies():
    """
    Installs the required dependencies for KitSec.
    """
    # Install subfinder
    subprocess.run(['go', 'install', '-v', 'github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest'])
    
    # Install assetfinder
#    subprocess.run(['go', 'install', 'github.com/tomnomnom/assetfinder@latest'])
    
    # Install waybackurls
#    subprocess.run(['go', 'install', 'github.com/tomnomnom/waybackurls@latest'])
    
    # Install Amass
    subprocess.run(['go', 'install', '-v', 'github.com/OWASP/Amass/v3/...@master'])