import click
import ipwhois
import hashlib
import requests
import paramiko
import ipaddress

import pandas as pd
from tqdm import tqdm
from bs4 import BeautifulSoup
from tabulate import tabulate
from Wappalyzer import Wappalyzer, WebPage

import sys
import html
import json
import base64
import platform
import binascii
import concurrent

from network import apply_capture, apply_disturb, apply_raid, apply_scan_ports, apply_cidr, ssh_logger
from utils import apply_transformation
from enumerator import apply_enumerator
from inject import apply_injector
from cve import query_cve

#todo: run kitsec from any directory

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
    ssh_logger(host, username, password)


@click.command()
@click.argument('url')
def capture(url):
    """
    Captures the request headers for a given URL.
    """
    apply_capture(url)


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


@click.command()
@click.option('--request', '-r', is_flag=True, default=False, help='Test subdomains and print http response for active ones.')
@click.option('--technology', '-t', is_flag=True, default=False, help='Analyze technology used by subdomains.')
@click.option('--active', '-a', is_flag=True, default=False, help='Use active enumeration.')
@click.argument('domain')
def enumerator(request, technology, active, domain):
    """Enumerate subdomains for a given domain."""
    apply_enumerator(request=request, technology=technology, active=active, domain=domain)


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


@click.command()
@click.argument('url', type=str)
@click.option('--num-attacks', '-a', type=int, default=6, help='Number of parallel threats to send requests from.')
@click.option('--num-requests', '-r', type=int, default=200, help='Number of requests to send from each threat.')
@click.option('--num-retries', '-y', type=int, default=4, help='Number of times to retry failed requests.')
@click.option('--pause-before-retry', '-p', type=int, default=3000, help='Number of milliseconds to wait before retrying a failed request.')
def raid(url, num_attacks, num_requests, num_retries, pause_before_retry):
    """
    Sends HTTP requests to a given URL with a specified number of threats and requests.
    """
    results = apply_raid(url, num_attacks, num_requests, num_retries, pause_before_retry)
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
    apply_injector(base_url, path)


@click.command()
@click.argument('company_name')
def cidr(company_name):
    """
    Look up the CIDR range for a company's domain name.
    """
    result = apply_cidr(company_name)
    click.echo(result)


@click.command()
@click.argument('company_name')
def cidr(company_name):
    """
    Look up the CIDR range for a company's domain name.
    """
    result = apply_cidr(company_name)
    click.echo(result)


@click.command()
@click.argument('product_name')
@click.option('--limit', '-l', type=int, default=10, help='Number of results to display (default=10)')
def cve(product_name, limit):
    """
    Retrieve CVE data for a specific product name (company name) and display it in a clean format.
    """
    cve_data = query_cve(product_name, limit)
    click.echo(cve_data)


cli.add_command(vps_logger)
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