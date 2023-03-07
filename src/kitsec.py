import os
import time
import gzip
import socket
import warnings
import subprocess
import urllib.parse
import hashlib

import requests
import paramiko
import concurrent
import pandas as pd
from tqdm import tqdm
from bs4 import BeautifulSoup
from tabulate import tabulate
from urllib.parse import urlparse
from Wappalyzer import Wappalyzer, WebPage

import click
import base64
import binascii
import html
import magic
import platform
import textwrap
import black


#add history http
#add tmux
#Add XSS scanner (https://github.com/s0md3v/XSStrike)

#ignore JAVA warnings on wappalyzer
warnings.filterwarnings("ignore", category=UserWarning, module='bs4')
warnings.filterwarnings("ignore", category=UserWarning, message=".*It looks like you're parsing an XML document using an HTML parser.*")
warnings.filterwarnings("ignore", message="""Caught 'unbalanced parenthesis at position 119' compiling regex""", category=UserWarning )

#add user agent rotation
#add proxy rotation


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

    Args:
    - host (str): The IP address of the remote VPS server to connect to.
    - username (str): The limited user account to use for connecting to the VPS server.
    - password (str): The password for the user account.

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


@click.command()
@click.argument('url')
def capture(url):
    """
    Captures the request headers for a given URL.

    Args:
    - url (str): The URL to capture request headers for.

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


@click.command()
@click.argument('data')
@click.option('--type', '-t', default='Base64', help='Type of decoding or hashing to apply. Options: URL, HTML, Base64, ASCII, Hex, Octal, Binary, MD5, SHA1, SHA256, BLAKE2B-160, GZIP. Default: Base64')
def convert(data, type):
    """
    Applies a specified decoding or hashing function to input data.

    Args:
    - data (str): The data to transform.
    - type (str): The type of transformation to apply. Options include: URL, HTML, Base64, ASCII, Hex, Octal, Binary, MD5, SHA1, SHA256, BLAKE2B-160, GZIP. Defaults to Base64 if not specified.

    Returns:
    - The transformed input data as a string.

    If the input data is text, the program will apply the specified transformation type and return the result.
    If the input data is binary, the program will apply the specified hashing function and return the resulting hash.
    If an invalid transformation type is specified, the program will return an error message.
    """
    detected_type = magic.from_buffer(data, mime=True)
    if detected_type.startswith('text'):
        if type == "URL":
            result = urllib.parse.unquote(data)
        elif type == "HTML":
            result = html.unescape(data)
        elif type == "Base64":
            decoded_bytes = base64.b64decode(data)
            result = decoded_bytes.decode('utf-8')
        elif type == "ASCII":
            try:
                result = bytearray.fromhex(data).decode()
            except ValueError:
                result = "Invalid ASCII input"
        elif type == "Hex":
            try:
                result = bytes.fromhex(data).decode('utf-8')
            except ValueError:
                result = "Invalid hex input"
        elif type == "Octal":
            try:
                result = ''.join([chr(int(octet, 8)) for octet in data.split()])
            except ValueError:
                result = "Invalid octal input"
        elif type == "Binary":
            try:
                result = ''.join([chr(int(octet, 2)) for octet in data.split()])
            except ValueError:
                result = "Invalid binary input"
        elif type == "GZIP":
            try:
                decoded = gzip.decompress(data)
                result = decoded.decode('utf-8')
            except Exception:
                result = "Invalid GZIP input"
        else:
            result = "Invalid decoding or hashing type"
    else:
        if type == "MD5":
            result = hashlib.md5(data).hexdigest()
        elif type == "SHA1":
            result = hashlib.sha1(data).hexdigest()
        elif type == "SHA256":
            result = hashlib.sha256(data).hexdigest()
        elif type == "BLAKE2B-160":
            result = hashlib.blake2b(data, digest_size=20).hexdigest()
        else:
            result = "Invalid decoding or hashing type"

    click.echo(result)


def shuffle(url):
    """
    Sends a GET request to the provided URL with shuffled proxies, ports, user agents,
    and headers.

    Args:
    - url (str): The URL to send the GET request to.

    Returns:
    - If the GET request is successful, returns the response text. Otherwise, returns None.

    The function shuffles a list of proxies, ports, user agents, and headers, and selects
    the first shuffled item for each parameter. It then creates a dictionary of shuffled proxy
    and header parameters and sends a GET request to the provided URL with these parameters.
    If the GET request is successful, the function returns the response text. Otherwise,
    it returns None.
    """
    # Define proxies, ports, user agents, and headers to shuffle
    proxies = ['1.2.3.4:8080', '5.6.7.8:3128', '9.10.11.12:80']
    ports = ['80', '8080', '3128']
    user_agents = ['Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36',
                   'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:54.0) Gecko/20100101 Firefox/54.0']
    headers = {'Accept-Language': 'en-US,en;q=0.5', 'Connection': 'keep-alive'}

    # Shuffle the proxies, ports, user agents, and headers
    random.shuffle(proxies)
    random.shuffle(ports)
    random.shuffle(user_agents)
    random.shuffle(headers)
    
    # Select the first shuffled item for each parameter
    proxy = proxies[0]
    port = ports[0]
    user_agent = user_agents[0]
    header = headers[0]
    
    # Create dictionary of shuffled proxy and header parameters
    proxies_dict = {'http': f'http://{proxy}:{port}', 'https': f'https://{proxy}:{port}'}
    headers_dict = {'User-Agent': user_agent, **header}
    
    # Send GET request with shuffled parameters and handle exceptions
    try:
        response = requests.get(url, proxies=proxies_dict, headers=headers_dict)
        response.raise_for_status()
        return response.text
    except (requests.exceptions.RequestException, ValueError):
        return None


def passive_enumerator(domain):
    """
    Uses Subfinder to enumerate subdomains for a given domain.

    Args:
        domain (str): The domain to enumerate subdomains for.

    Returns:
        set: A set of subdomains.
    """
    # Run Subfinder and capture output
    with open(os.devnull, 'w') as nullfile:
        subfinder_output = subprocess.check_output(['subfinder', '-d', domain], stderr=nullfile)

    # Convert output to set of subdomains
    subdomains = set(subfinder_output.decode('utf-8').strip().split('\n'))

    # Return set of subdomains
    return subdomains


def active_enumerator(domain):
    """
    Enumerates subdomains for a given domain, and checks which ones are active.
    Args:
        domain (str): The domain to enumerate subdomains for.
    Returns:
        set or None: A set of subdomains, or None if no subdomains were found.
    """
    subdomains = set()
    
    # Check if subdomains directory exists
    dir_path = "../lists/active_enumerator"
    if not os.path.isdir(dir_path):
        raise FileNotFoundError(f"Subdomains directory '{dir_path}' not found")
    
    # Get list of subdomain files in directory
    file_names = [file_name for file_name in os.listdir(dir_path) if os.path.isfile(os.path.join(dir_path, file_name)) and file_name.endswith(".txt")]
    total_files = len(file_names)
    
    # Enumerate subdomains from each file and check if active
    for i, file_name in enumerate(file_names):
        file_path = os.path.join(dir_path, file_name)
        with open(file_path, "r") as subdomain_file:
            for line in tqdm(subdomain_file, desc="Active enumeration", unit="Subdomains"):
                subdomain = line.strip()
                full_domain = subdomain + "." + domain
                try:
                    # Send a HEAD request to check if the subdomain is active
                    response = requests.head("https://" + full_domain, timeout=3)
                    if response.status_code < 400:
                        subdomains.add(subdomain)
                
                # Ignore exceptions and continue to the next subdomain
                except:
                    pass
    
    # Return set of active subdomains or empty set if none were found
    if subdomains:
        return subdomains
    else:
        return set()


def fetch_response(subdomains: List[str], technology: bool) -> List[List[str]]:
    """
    Fetches the HTTP response codes and reasons for a list of subdomains.

    Args:
    - subdomains (List[str]): A list of subdomains to fetch responses for.
    - technology (bool): Whether to also fetch the technologies used by each subdomain.

    Returns:
    - A list of lists, where each sub-list contains the following fields for a subdomain:
      - Subdomain name (str)
      - HTTP status code (int)
      - HTTP status reason (str)
      - List of technologies used by the subdomain (if technology is True), or an empty string (if technology is False).
    """
    # Initialize empty response table and create a session object for TCP connection reuse
    response_table = []
    session = requests.Session()
    
    # Fetch response for each subdomain in the list
    for subdomain in tqdm(subdomains, desc='Fetching response', unit='subdomain', leave=False):
        try:
            # Make HTTP GET request with timeout of 5 seconds
            response = session.get(f'http://{subdomain}', timeout=5)
            response_table.append([subdomain, response.status_code, response.reason, ''])
            
            # Fetch technology if specified
            if technology:
                tech = fetch_tech(subdomain)
                response_table[-1][-1] = tech
            
            # Add a delay of 0.5 seconds to avoid overloading the target website
            time.sleep(0.5)
        
        # Handle timeout and connection errors
        except requests.exceptions.Timeout:
            print(f"Skipped '{subdomain}'")
            continue
        except requests.exceptions.ConnectionError:
            print(f"Skipped '{subdomain}'")
            continue
        
        # Handle other exceptions
        except Exception as e:
            print(f"Skipped '{subdomain}': {str(e)}")
            continue
    
    # Return response table
    return response_table


def fetch_tech(url):
    """
    Fetches the technologies used by a website using Wappalyzer.

    Args:
    - url (str): The URL of the website to analyze.

    Returns:
    - A list of strings representing the technologies used by the website.
    - If an error occurs while fetching the technologies, returns None.
    """
    # Ensure URL starts with http(s)
    if not url.startswith('http'):
        url = 'https://' + url
    
    # Fetch web page and analyze with Wappalyzer
    webpage = WebPage.new_from_url(url)
    wappalyzer = Wappalyzer.latest()
    technologies = []
    
    # Retry fetching up to 5 times in case of error
    max_retries = 5
    retry_count = 0
    while retry_count < max_retries:
        try:
            for tech in wappalyzer.analyze(webpage):
                technologies.append(tech)
            return technologies
        except Exception as e:
            # Print error message and wait 5 seconds before retrying
            retry_count += 1
            print(f"Error fetching technologies for {url}: {e}")
            time.sleep(5)
    
    # Max retries reached, return None
    print(f"Max retries reached for {url}")
    return None


@click.command()
@click.argument('domain')
@click.option('-r', '--request', is_flag=True, help='Test subdomains and print http response for active ones')
@click.option('-t', '--technology', is_flag=True, help='Analyze technology used by subdomains')
@click.option('-a', '--active', is_flag=True, help='Use active subdomain enumeration')
def enumerator(domain, request, technology, active):
    """
    Enumerates subdomains for a given domain using Subfinder and active enumeration.

    Args:
        domain (str): The domain to enumerate subdomains for.
        request (bool): Flag to indicate if subdomains should be tested and http response printed for active ones.
        technology (bool): Flag to indicate if technology used by subdomains should be analyzed.
        active (bool): Flag to indicate if active subdomain enumeration should be used.

    Returns:
        pandas.DataFrame: A DataFrame containing the enumerated subdomains.
    """
    # Get subdomains using Subfinder
    subdomains = passive_enumerator(domain)

    if active:
        # Enumerate subdomains using active enumeration
        active_subdomains = active_enumerator(domain)
        # Add the active subdomains to the set of subdomains
        subdomains.update(active_subdomains)

    if request or technology:
        # Test subdomains and/or analyze technology used by subdomains
        response_table = fetch_response(subdomains, technology)
        if technology:
            # sort response_table by status in ascending order
            response_table = sorted(response_table, key=lambda x: -x[1])
            click.echo(tabulate(response_table, headers=['Subdomain', 'Status', 'Reason', 'Technology']))
        else:
            # sort response_table by status in ascending order
            response_table = sorted(response_table, key=lambda x: x[1])
            click.echo(tabulate(response_table, headers=['Subdomain', 'Status', 'Reason']))

    else:
        # Just print the subdomains
        subdomains_list = list(subdomains)
        with tqdm(total=len(subdomains_list), desc='Enumerating subdomains', unit='subdomain') as pbar:
            subdomains_list = [[subdomain] for subdomain in subdomains_list]
            click.echo(tabulate(subdomains_list, headers=['Subdomain']))
            pbar.update(len(subdomains_list))


@click.command()
@click.option('--url', required=True, help='The URL to send the request to.')
@click.option('--method', default='GET', help='The HTTP method to use.')
@click.option('--payload', help='The payload to include in the request body.')
@click.option('--headers', help='The headers to include in the request.')
@click.option('--cookies', help='The cookies to include in the request.')
@click.option('--count', default=1, help='The number of times to repeat the request.')
def disturb(url, method, payload, headers, cookies, count):
    """
    Sends multiple HTTP requests to the specified URL with the same payload.

    Args:
    - url (str): The URL to send the request to.
    - method (str): The HTTP method to use. Default: 'GET'
    - payload (str): The payload to include in the request body. Default: None
    - headers (dict): The headers to include in the request. Default: None
    - cookies (dict): The cookies to include in the request. Default: None
    - count (int): The number of times to repeat the request. Default: 1
    """
    responses = []
    for i in range(count):
        response = requests.request(method, url, data=payload, headers=headers, cookies=cookies)
        responses.append(response)
    return responses


@click.command()
@click.argument('url')
@click.option('--num-threats', '-t', default=6, help='Number of parallel threats to send requests from')
@click.option('--num-requests', '-r', default=200, help='Number of requests to send from each threat')
@click.option('--num-retries', '-n', default=4, help='Number of times to retry failed requests')
@click.option('--pause-before-retry', '-p', default=3000, help='Number of milliseconds to wait before retrying a failed request')
def raid(url, num_threats, num_requests, num_retries, pause_before_retry):
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
@click.argument('url')
@click.option('-c', '--common-ports', is_flag=True, default=False,
              help='Scan only the most common HTTP ports (80, 8080, and 443)')
def portscan(url, common_ports):
    """
    Performs a TCP port scan on a specified hostname or URL and a range of ports.

    Args:
    - url (str): the hostname or URL of the target host
    - common_ports (bool): whether to scan only the most common HTTP ports (80, 8080, and 443)

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


@click.command()
@click.argument('base_url')
@click.argument('path', default='../lists/injector')
def inject(base_url, path):
    """
    Sends HTTP GET requests to a specified base URL with a given list of paths.

    Usage: python filename.py <base_url> <path>

    Arguments:
    - base_url (str): The base URL to send requests to. The URL must include the protocol (http or https).
    - path (str): The path to a file or directory containing a list of paths to send requests to.

    If the path is a directory, the program will iterate through each file in the directory and send a request for each path in the file.
    If the path is a regular file, the program will send a request for each path in the file.
    For each request sent, the program will print the URL and response code to the console if the response code is 200.
    If the path does not exist, the program will print an error message to the console.
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
                    progress_bar = tqdm(paths, desc=filename, position=0, leave=True)
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


cli.add_command(vps_logger)
cli.add_command(collab)
cli.add_command(capture)
cli.add_command(convert)
cli.add_command(enumerator)
cli.add_command(disturb)
cli.add_command(raid)
cli.add_command(portscan)
cli.add_command(inject)


if __name__ == '__main__':
    cli()