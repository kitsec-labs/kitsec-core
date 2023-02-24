import os
import time
import click
import requests
import subprocess
import pandas as pd
from tqdm import tqdm
from tabulate import tabulate

#todo: add cred_tester
#add IP shuffler/VPN
#todo : add hackerone crawler for enumerator/testor
#todo : add bugcrowd crawler for enumerator/testor
#todo : add yes we hack crawler for enumerator/testor


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
@click.option('--path', default='.', help='Path to project directory')
def pydeps(path):
    """Install all Python dependencies specified in requirements.txt"""
    req_file = os.path.join(path, 'kitsec-core', 'requirements.txt')
    try:
        subprocess.check_call(['pip', 'install', '-r', req_file])
    except subprocess.CalledProcessError:
        click.echo('Error: Failed to install dependencies.')

@click.command()
@click.argument('domain')
@click.option('-t', '--test', is_flag=True, help='Test subdomains and print http response for active ones')
@click.option('-f', '--filter-domain', multiple=True, help='Filter 404 domains')
def enumerator(domain, test, filter_domain):
    """
    Enumerates subdomains for a given domain using Subfinder.

    Args:
        domain (str): The domain to enumerate subdomains for.
        test (bool): Flag to indicate if subdomains should be tested and http response printed for active ones.
        filter_domain (list): List of subdomains to filter from output based on HTTP response.

    Returns:
        pandas.DataFrame: A DataFrame containing the enumerated subdomains.
    """
    # Call Subfinder and capture output
    with open('/dev/null', 'w') as nullfile:
        subfinder_output = subprocess.check_output(['subfinder', '-d', domain], stderr=nullfile)

    # Split output into lines and remove any duplicates
    subdomains = set(subfinder_output.decode('utf-8').strip().split('\n'))

    # Filter subdomains based on HTTP response
    filtered_subdomains = []
    if filter_domain:
        for subdomain in subdomains:
            if subdomain not in filter_domain:
                try:
                    response = requests.get(f'http://{subdomain}')
                    if response.status_code != 404:
                        filtered_subdomains.append(subdomain)
                except requests.exceptions.RequestException:
                    pass
    else:
        filtered_subdomains = subdomains

    # Create a Pandas DataFrame with the subdomains
    df = pd.DataFrame(filtered_subdomains, columns=['Subdomain'])

    if test:
        # Test subdomains and print http response for active ones
        table = []
        with tqdm(total=len(filtered_subdomains), desc='Testing subdomains', unit='subdomain') as pbar:
            for subdomain in filtered_subdomains:
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

cli.add_command(pydeps)
cli.add_command(godeps)
cli.add_command(injector)
cli.add_command(enumerator)
cli.add_command(intruder)

if __name__ == '__main__':
    cli() 