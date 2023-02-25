import os
import time
import click
import platform
import requests
import paramiko
import subprocess
import pandas as pd
from tqdm import tqdm
from tabulate import tabulate

#todo: fix active subdomain enumeration
#todo : Enrich with  wappalyzer informations about the website https://github.com/chorsley/python-Wappalyzer
#todo: add web fuzzing: https://github.com/ffuf/ffuf
#todo: port checker https://github.com/projectdiscovery/naabu
#check: https://github.com/six2dez/reconftw


@click.group()
def cli():
    pass

@click.command()
@click.argument('godeps', default='github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest')
def godeps(godeps):
    """Install subfinder using Go"""
    cmd = ["go", "install", "-v", godeps]
    with tqdm(total=100, desc="Installing go dependencies") as pbar:
        try:
            subprocess.check_call(cmd)
            pbar.update(100)
        except subprocess.CalledProcessError as e:
            pbar.write(f"Installation failed with exit code {e.returncode}")
            return
    click.echo("go dependencies installed successfully!")

@click.command()
@click.option('--force', is_flag=True, help='Force installation, even if dependencies are already installed.')
def deps(force):
    os_name = platform.system()
    if os_name == 'Darwin':  # check if running on a Mac
        click.echo("Detected Mac OS. Installing Homebrew...")
        subprocess.run(['/bin/bash', '-c', '$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)'])  # install Homebrew using the official script
        click.echo("Installing Go...")
        subprocess.run(['brew', 'install', 'go'])  # install Go using Homebrew
        click.echo("Installing Go deps...")
        with tqdm(total=100, desc="Installing Go deps", unit="%", ncols=80) as pbar:
            if force:
                subprocess.run(['go', 'install', '-u', 'github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest'], stdout=subprocess.PIPE, universal_newlines=True, bufsize=1)
            else:
                subprocess.run(['go', 'install', 'github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest'], stdout=subprocess.PIPE, universal_newlines=True, bufsize=1)
            pbar.update(100)
        click.echo("Done!")
    elif os_name == 'Linux':  # check if running on Linux
        click.echo("Detected Linux OS. Installing Go...")
        subprocess.run(['sudo', 'apt', 'install', '-y', 'golang-go'])  # install Go using apt package manager on Ubuntu-based systems
        click.echo("Installing Go deps...")
        with tqdm(total=100, desc="Installing Go deps", unit="%", ncols=80) as pbar:
            if force:
                subprocess.run(['go', 'install', '-u', 'github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest'], stdout=subprocess.PIPE, universal_newlines=True, bufsize=1)
            else:
                subprocess.run(['go', 'install', 'github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest'], stdout=subprocess.PIPE, universal_newlines=True, bufsize=1)
            pbar.update(100)
        click.echo("Done!")
    elif os_name == 'Windows':  # check if running on Windows
        click.echo("Detected Windows OS. Installing Go...")
        subprocess.run(['choco', 'install', '-y', 'golang'])  # install Go using Chocolatey package manager
        click.echo("Installing Go deps...")
        with tqdm(total=100, desc="Installing Go deps", unit="%", ncols=80) as pbar:
            if force:
                subprocess.run(['go', 'install', '-u', 'github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest'], stdout=subprocess.PIPE, universal_newlines=True, bufsize=1)
            else:
                subprocess.run(['go', 'install', 'github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest'], stdout=subprocess.PIPE, universal_newlines=True, bufsize=1)
            pbar.update(100)
        click.echo("Done!")
    else:
        click.echo("Sorry, this function does not support your operating system.")

#@click.command()
#@click.option('--hostname', prompt='Enter the hostname', help='The hostname of the Linode VPS')
#@click.option('--username', prompt='Enter the username', help='The username to log in with')
#@click.password_option(confirmation_prompt=True, help='The password to log in with')
#def linode(hostname, username, password):
#    """
#    Logs into a Linode VPS using SSH.
#    """
    # Create an SSH client
#    ssh_client = paramiko.SSHClient()

    # Automatically add the host key
#    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    # Connect to the Linode VPS
#    ssh_client.connect(hostname=hostname, username=username, password=password)

    # Execute a command on the Linode VPS
#    stdin, stdout, stderr = ssh_client.exec_command('ls')

    # Print the output of the command
#    click.echo(stdout.read().decode())

    # Close the SSH client
#    ssh_client.close()


@click.command()
@click.argument('domain')
@click.option('-t', '--test', is_flag=True, help='Test subdomains and print http response for active ones')
def enumerator(domain, test):
    """
    Enumerates subdomains for a given domain using Subfinder.

    Args:
        domain (str): The domain to enumerate subdomains for.
        test (bool): Flag to indicate if subdomains should be tested and http response printed for active ones.

    Returns:
        pandas.DataFrame: A DataFrame containing the enumerated subdomains.
    """
    # Call Subfinder and capture output
    with open(os.devnull, 'w') as nullfile:
        subfinder_output = subprocess.check_output(['subfinder', '-d', domain], stderr=nullfile)

    # Split output into lines and remove any duplicates
    subdomains = set(subfinder_output.decode('utf-8').strip().split('\n'))

    # Add active subdomains from the list
#    active_subdomains = []
#    with open(os.path.join(os.path.dirname(__file__), '../lists/subdomains')) as subdomains_file:
#        subdomains_list = subdomains_file.read().splitlines()
#        with tqdm(total=len(subdomains_list), desc='Adding active subdomains', unit='subdomain') as pbar:
#            for subdomain in subdomains_list:
#                try:
#                    response = requests.get(f'http://{subdomain}.{domain}')
#                    if response.status_code != 404:
#                        active_subdomains.append(f'{subdomain}.{domain}')
#                except requests.exceptions.RequestException:
#                    pass
#                pbar.update(1)

    # Combine subdomains and active_subdomains and remove duplicates
#    subdomains |= set(active_subdomains)

    # Create a Pandas DataFrame with the subdomains
    df = pd.DataFrame(subdomains, columns=['Subdomain'])

    if test:
        # Test subdomains and print http response for active ones
        table = []
        with tqdm(total=len(subdomains), desc='Testing subdomains', unit='subdomain') as pbar:
            for subdomain in subdomains:
                try:
                    response = requests.get(f'http://{subdomain}')
                    table.append([subdomain, response.status_code, response.reason])
                except requests.exceptions.RequestException:
                    pass
                pbar.update(1)
        sorted_table = sorted(table, key=lambda row: row[1], reverse=True)
        click.echo(tabulate(sorted_table, headers=['Subdomain', 'Status', 'Reason']))
    else:
        # Just print the subdomains
        subdomains_list = df['Subdomain'].tolist()
        with tqdm(total=len(subdomains_list), desc='Enumerating subdomains', unit='subdomain') as pbar:
            subdomains_list = [[subdomain] for subdomain in subdomains_list]
            click.echo(tabulate(subdomains_list, headers=['Subdomain']))
            pbar.update(len(subdomains_list))


@click.command()
@click.argument('url')
@click.option('--num-threats', '-t', default=6, help='Number of parallel threats to send requests from')
@click.option('--num-requests', '-r', default=200, help='Number of requests to send from each threat')
@click.option('--num-retries', '-n', default=4, help='Number of times to retry failed requests')
@click.option('--pause-before-retry', '-p', default=3000, help='Number of milliseconds to wait before retrying a failed request')
def intruder(url, num_threats, num_requests, num_retries, pause_before_retry):
    """
    Sends HTTP requests to a given URL with a specified number of threats and requests.

    Args:
        url (str): The URL to send the requests to (i.e. subdomain.domain.com).
        num_threats (int, optional): The number of parallel threats to send requests from. Defaults to 6.
        num_requests (int, optional): The number of requests to send from each threat. Defaults to 200.
        num_retries (int, optional): The number of times to retry failed requests. Defaults to 4.
        pause_before_retry (int, optional): The number of milliseconds to wait before retrying a failed request. 
            Defaults to 3000.
    """
    if not url.startswith('http://') and not url.startswith('https://'):
        url = 'https://' + url
    prepared_request = requests.Request('GET', url).prepare()
    results = []
    with requests.Session() as session:
        adapter = requests.adapters.HTTPAdapter(max_retries=num_retries)
        session.mount('http://', adapter)
        session.mount('https://', adapter)
        pool = session.send
        for i in range(num_threats):
            threat_results = []
            with tqdm(total=num_requests, desc=f'Threat {i+1}') as pbar:
                for j in range(num_requests):
                    response = pool(prepared_request)
                    threat_results.append(response)
                    if response.status_code == 200:
                        break
                    time.sleep(pause_before_retry/1000)
                    pbar.update(1)
            results.append(threat_results)
    click.echo(results)


@click.command()
@click.argument('base_url')
@click.argument('path', default='../lists/paths')
def injector(base_url, path):
    # Add http or https prefix if missing
    if not base_url.startswith('http'):
        base_url = 'http://' + base_url

    if os.path.isdir(path):
        for filename in os.listdir(path):
            filepath = os.path.join(path, filename)
            if os.path.isfile(filepath):
                with open(filepath) as f:
                    paths = f.read().splitlines()
                    progress_bar = tqdm(paths, desc=filename, position=0, leave=True)
                    for p in progress_bar:
                        url = f"{base_url}/{p}"
                        response = requests.get(url)
                        if response.status_code == 200:
                            click.echo(f"{url} - {response.status_code}")
    elif os.path.isfile(path):
        with open(path) as f:
            paths = f.read().splitlines()
            progress_bar = tqdm(paths, desc=os.path.basename(path), position=0, leave=True)
            for p in progress_bar:
                url = f"{base_url}/{p}"
                response = requests.get(url)
                if response.status_code == 200:
                    click.echo(f"{url} - {response.status_code}")
    else:
        click.echo(f"{path} does not exist")


cli.add_command(deps)
cli.add_command(godeps)
cli.add_command(linode)
cli.add_command(injector)
cli.add_command(enumerator)
cli.add_command(intruder)

if __name__ == '__main__':
    cli() 