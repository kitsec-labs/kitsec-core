# Standard library modules
import base64
import binascii
import concurrent
import hashlib
import html
import json
import os
import platform
import sys

# Third-party modules
import click
import ipaddress
import ipwhois
import paramiko
import requests
import pandas as pd
from tqdm import tqdm
from bs4 import BeautifulSoup
from tabulate import tabulate
from Wappalyzer import Wappalyzer, WebPage

# Local modules
from cve import query_cve
from enumerator import apply_enumerator
from fuzz import apply_file_format_fuzz, apply_path_fuzz
from network import (apply_capture, apply_cidr, apply_disturb, apply_storm,
                    apply_scan_ports, apply_check_certificate)
from dependencies import install_dependencies
from utils import apply_transformation


#todo: run kitsec from any directory

@click.group()
def cli():
    """
    KitSec - A CLI tool for security testing and reconnaissance.
    """
    pass

@click.command()
def deps():
    """
    Installs the necessary dependencies for KitSec.
    """
    click.echo("Installing dependencies...")
    install_dependencies()
    click.echo("Dependencies installed successfully!")


@click.command()
@click.option('--host', prompt='Enter the IP address of the VPS server to connect to')
@click.option('--username', prompt='Enter the limited user account to use for connecting to the VPS server')
@click.option('--password', prompt='Enter the password for the user account', hide_input=True)
def vps(host, username, password):
    """
    Connects to a remote server using SSH and logs in as the specified user.

    Args:
    - host (str): The IP address or hostname of the remote server.
    - username (str): The username to use for SSH authentication.
    - password (str): The password to use for SSH authentication.

    Returns:
    - None. The function logs into the remote server and starts an interactive session.
    """
    client = paramiko.client.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(host, username=username, password=password)
    client.invoke_shell()
    while True:
        command = input("> ")
        if command == "exit":
            break
        _, stdout, _ = client.exec_command(command)
        output = stdout.read().decode("utf-8")
        print(output)
    client.close()



@click.command()
@click.argument('url')
def capture(url):
    """
    Captures the request headers for a given URL.
    """
    apply_capture(url)

@click.command()
@click.argument('url')
@click.help_option('--help', '-h')
def certificate(url):
    """
    Checks the SSL/TLS certificate information for a given URL.
    """
    hostname = url.split('//')[-1].split('/')[0]
    apply_check_certificate(hostname)

@click.command()
@click.argument('data')
@click.option('--type', '-t', 'transformation_type', type=click.Choice(['URL', 'HTML', 'Base64', 'ASCII', 'Hex', 'Octal', 'Binary', 'MD5', 'SHA1', 'SHA256', 'BLAKE2B-160', 'GZIP']), default='Base64', help='The type of transformation to apply to the input data.')
@click.help_option('--help', '-h')
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



@click.command()
@click.option('--request', '-r', is_flag=True, default=False, help='Test subdomains and print http response for active ones.')
@click.option('--technology', '-t', is_flag=True, default=False, help='Analyze technology used by subdomains.')
@click.option('--active', '-a', is_flag=True, default=False, help='Use active enumeration.')
@click.argument('domain')
@click.option('-h', '--help', 'display_help', is_flag=True, help='Display this help message')
def enumerator(request, technology, active, domain, display_help):
    """
    Enumerate subdomains for a given domain.
    """
    if display_help:
        click.echo(enumerator.get_help(click.Context(enumerator)))
    else:
        apply_enumerator(request=request, technology=technology, active=active, domain=domain)



@click.command()
@click.argument('url', required=True)
@click.option('-m', '--method', default='GET', help='HTTP method to use')
@click.option('-p', '--payload', default='', help='Payload to include in the request body')
@click.option('-H', '--headers', default='', help='Headers to include in the request')
@click.option('-c', '--cookies', default='', help='Cookies to include in the request')
@click.option('-n', '--count', default=1, type=int, help='Number of times to repeat the request')
@click.option('--show-help', '-h', is_flag=True, help='Show help message.')
def disturb(url, method, payload, headers, cookies, count, show_help):
    """
    Sends multiple HTTP requests to the specified URL with the same payload.
    """
    if show_help:
        click.echo(disturb.get_help(click.Context(disturb)))
    else:
        responses = disturb(url, method, payload, headers, cookies, count)
        for i, response in enumerate(responses):
            click.echo(f'Response {i + 1}: {response.status_code} - {response.reason}')



@click.command()
@click.argument('url')
@click.option('--num-attacks', '-a', type=int, default=6, help='Number of parallel threats to send requests from.')
@click.option('--num-requests', '-r', type=int, default=200, help='Number of requests to send from each threat.')
@click.option('--num-retries', '-y', type=int, default=4, help='Number of times to retry failed requests.')
@click.option('--pause-before-retry', '-p', type=int, default=3000, help='Number of milliseconds to wait before retrying a failed request.')
@click.option('-h', '--help', 'display_help', is_flag=True, help='Display this help message')
def storm(url, num_attacks, num_requests, num_retries, pause_before_retry, display_help):
    """
    Sends HTTP requests to a given URL with a specified number of threats and requests.
    """
    if display_help:
        click.echo(storm.get_help(click.Context(storm)))
    else:
        results = apply_storm(url, num_attacks, num_requests, num_retries, pause_before_retry)
        click.echo(results)


@click.command()
@click.argument('url')
@click.option('-c', '--common-ports', is_flag=True, help='Scan only the most common HTTP ports (80, 8080, and 443)')
def portscan(url, common_ports):
    """
    Performs a TCP port scan on a specified hostname or URL and a range of ports.
    """
    open_ports = apply_scan_ports(url, common_ports)
    click.echo('\nOpen Ports:')
    for port in open_ports:
        click.echo(port)


@click.command()
@click.argument('base_url')
@click.option('-p', '--path', default='../lists/fuzz/path_fuzz', help='The path to a file or directory containing a list of paths to send requests to. Default: ../lists/injector')
@click.option('-f', '--file-fuzz', is_flag=True, help='Use file format fuzzing')
@click.help_option('--help', '-h')
def fuzz(base_url, path, file_fuzz):
    """
    Sends HTTP GET requests to a specified base URL with a given list of paths.

    Args:
    - base_url (str): The base URL to send requests to. The URL must include the protocol (http or https).

    Options:
    - path (str): The path to a file or directory containing a list of paths to send requests to. 
    Default: ../lists/fuzz/path_fuzz
    - file-fuzz (bool): Whether to use file format fuzzing or not

    Returns:
    - None. For each request sent, the program will print the URL and response code to the console if the response code is 200.
    """

    # Add http or https prefix if missing
    if not base_url.startswith('http'):
        base_url = 'http://' + base_url

    if file_fuzz:
        apply_file_format_fuzz(base_url)

    if os.path.isdir(path) and not file_fuzz:
        apply_path_fuzz(base_url, path)

    elif os.path.isfile(path) and not file_fuzz:
        apply_path_fuzz(base_url, path)

    else:
        click.echo(f"{path} does not exist")



@click.command()
@click.argument('company_name')
@click.help_option('--help', '-h')
def cidr(company_name):
    """
    Look up the CIDR range for a company's domain name.
    """
    result = apply_cidr(company_name)
    click.echo(result)


@click.command()
@click.argument('product_name')
@click.option('--limit', '-l', type=int, default=10, help='Number of results to display (default=10)')
@click.help_option('--help', '-h')
def cve(product_name, limit):
    """
    Retrieve CVE data for a specific product name (company name) and display it in a clean format.
    """
    cve_data = query_cve(product_name, limit)
    click.echo(cve_data)


cli.add_command(deps)
cli.add_command(vps)
cli.add_command(certificate)
cli.add_command(capture)
cli.add_command(convert)
cli.add_command(enumerator)
cli.add_command(disturb)
cli.add_command(storm)
cli.add_command(portscan)
cli.add_command(fuzz)
cli.add_command(cve)
cli.add_command(cidr)


if __name__ == '__main__':
    cli()