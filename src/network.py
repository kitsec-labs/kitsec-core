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

def scan_ports(url, common_ports=False):
    """
    Performs a TCP port scan on a specified hostname or URL and a range of ports.

    Args:
    - url (str): The hostname or URL of the target host.

    Options:
    - common-ports (bool): Whether to scan only the most common HTTP ports (80, 8080, and 443).

    Returns:
    - None. Prints the open ports found on the target host.
    """
    # Add a scheme to the URL if it is not present
    if not url.startswith('http://') and not url.startswith('https://'):
        url = 'https://' + url

    # Parse the URL to extract the hostname
    hostname = urlparse(url).hostname or url

    # Resolve the hostname to an IP address
    ip_address = socket.gethostbyname(hostname)

    open_ports = []

    # Define a function to scan a single port
    def scan_port(port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.1)
        try:
            sock.connect((ip_address, port))
            open_ports.append(f"{hostname}:{port}")
        except:
            pass
        finally:
            sock.close()

    # Scan only the most common HTTP ports if the --common-ports flag is set
    if common_ports:
        ports = [80, 8080, 443]
    else:
        ports = range(1, 65536)

    # Use multi-threading to scan ports in parallel
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        futures = [executor.submit(scan_port, port) for port in ports]
        with tqdm(total=len(futures), desc="Scanning Ports", unit="ports") as progress:
            for future in concurrent.futures.as_completed(futures):
                progress.update(1)

    # Print the open ports
    click.echo('\nOpen Ports:')
    for port in open_ports:
        click.echo(port)

import urllib.parse
import requests
import textwrap
import click

def capture_request(url):
    """
    Captures the request headers for a given URL.

    Returns:
    - Prints a string containing the captured request headers, including method, hostname, path, cookies, and all other headers sent with the request.
    """
    # Make a request to the given URL and capture the request headers
    response = requests.get(url)
    headers = response.request.headers

    # Parse the URL to get the hostname and path
    parsed_url = urllib.parse.urlparse(url)
    hostname = parsed_url.hostname
    path = parsed_url.path

    # Construct the request info string
    request_info = f"{response.request.method} {path} HTTP/1.1\n"
    request_info += f"Host: {hostname}\n"
    
    cookie_lines = headers.get("Cookie", "").split("; ")
    cookies = "\n".join(cookie_lines)
    request_info += f"Cookie: {cookies}\n"
    
    request_info += "\n".join([f"{header}: {value}" for header, value in headers.items() if header not in ["Host", "User-Agent", "Cookie"]])
    request_info += "\n\n"
    
    # Add response headers
    request_info += "Response headers:\n"
    request_info += textwrap.indent("\n".join([f"  {header}: {value}" for header, value in response.headers.items()]), "  ")
    request_info += "\n"
    
    print(request_info)

import requests

def disturb(url, method='GET', payload='', headers={}, cookies={}, count=1):
    """
    Sends multiple HTTP requests to the specified URL with the same payload.

    Args:
    - url (str): The URL to send requests to.
    - method (str): The HTTP method to use (default is 'GET').
    - payload (str): The payload to include in the request body (default is '').
    - headers (dict): The headers to include in the request (default is {}).
    - cookies (dict): The cookies to include in the request (default is {}).
    - count (int): The number of times to repeat the request (default is 1).

    Returns:
    - A list of HTTP responses for each request sent.
    """
    responses = []
    for i in range(count):
        response = requests.request(method, url, data=payload, headers=headers, cookies=cookies)
        responses.append(response)
    return responses
