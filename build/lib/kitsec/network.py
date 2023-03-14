# Standard library modules
import datetime
import socket
import ssl
import time

# Third-party modules
import click
import concurrent.futures
import ipwhois
import paramiko
import requests
from tqdm import tqdm
from urllib.parse import urlparse

# Built-in modules
import pty
import random
import textwrap
import urllib


def apply_check_certificate(hostname, port=443):
    """
    Check the SSL/TLS certificate for the specified host and port.

    Args:
    - hostname (str): The hostname to check the certificate for.
    - port (int): The port to connect to. Default is 443.

    Returns:
    - None

    This function creates a socket object and wraps it with an SSL context to
    establish a secure connection with the specified host and port. It then gets
    the certificate from the connection and extracts relevant information such
    as the notBefore and notAfter fields.

    If the certificate is expired or expiring soon (within 30 days), this function
    outputs a message to the console using the click.echo() function. It then outputs
    some information about the certificate such as the hostname, notBefore, and notAfter fields.

    """
   # Function for checking SSL/TLS certificate
    # Create a socket object and wrap it with an SSL context
    context = ssl.create_default_context()
    conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=hostname)

    # Connect to the server and get the certificate
    conn.connect((hostname, port))
    cert = conn.getpeercert()

    # Extract relevant information from the certificate
    not_before = datetime.datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
    not_after = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
    remaining_days = (not_after - datetime.datetime.now()).days

    # Check if the certificate is expired or expiring soon
    if remaining_days <= 0:
        click.echo(f"The SSL/TLS certificate for {hostname} has expired!")
    elif remaining_days <= 30:
        click.echo(f"The SSL/TLS certificate for {hostname} will expire in {remaining_days} days.")

    # Output some information about the certificate
    click.echo(f"Hostname: {hostname}")
    click.echo(f"Not Before: {not_before}")
    click.echo(f"Not After: {not_after}")


def apply_scan_ports(url, common_ports=False):
    """
    Performs a TCP port scan on a specified hostname or URL and a range of ports.

    Args:
    - url (str): The hostname or URL of the target host.

    Options:
    - common-ports (bool): Whether to scan only the most common HTTP ports (80, 8080, and 443).

    Returns:
    - A list of open ports found on the target host.
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
        for future in concurrent.futures.as_completed(futures):
            pass

    # Return the open ports
    return open_ports



def apply_capture(url):
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
    
    # Check for missing headers
    missing_headers = []
    for header in ["X-XSS-Protection", "X-Content-Type-Options", "Strict-Transport-Security", "Content-Security-Policy", "Referrer-Policy", "Feature-Policy"]:
        if header not in headers:
            missing_headers.append(header)
    
    # Add the "Response headers" section
    request_info += "Response headers:\n"
    request_info += textwrap.indent("\n".join([f"  {header}: {value}" for header, value in response.headers.items()]), "  ")
    request_info += "\n"
    
    # Add the "Connection" header
    connection_header = headers.get("Connection", "")
    if connection_header:
        request_info += f"Connection: {connection_header}\n"
    
    cookie_lines = headers.get("Cookie", "").split("; ")
    cookies = "\n".join(cookie_lines)
    request_info += f"Cookie: {cookies}\n"
    
    request_info += "\n".join([f"{header}: {value}" for header, value in headers.items() if header not in ["Host", "User-Agent", "Cookie", "Connection"]])
    request_info += "\n\n"
    
    # Add the "Missing headers" section if there are missing headers
    if missing_headers:
        request_info += "Missing headers:\n"
        request_info += f"{', '.join(missing_headers)}\n"
    
    print(request_info)



def apply_disturb(url, method='GET', payload='', headers={}, cookies={}, count=1):
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


def storm(url, num_attacks=6, num_requests=200, num_retries=4, pause_before_retry=3000):
    """
    Sends HTTP GET requests to the specified URL with a specified number of attacks and requests.

    Args:
    - url (str): The URL to send GET requests to.
    - num_attacks (int): The number of attacks to execute.
    - num_requests (int): The number of requests to send in each attack.
    - num_retries (int): The number of times to retry failed requests.
    - pause_before_retry (int): The number of milliseconds to pause before retrying failed requests.

    Returns:
    - A list of response objects for each attack.

    This function sends a GET request to the specified URL using the requests module. The URL is automatically
    prefixed with 'https://' if it doesn't start with either 'http://' or 'https://'. The function then sends
    a specified number of attacks to the URL, with a specified number of requests in each attack. For each request,
    the function checks whether the response status code is 200. If it's not, the function retries the request a
    specified number of times before giving up. The function returns a list of response objects for each attack.
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
        for i in range(num_attacks):
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
    return results


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


def apply_storm(url, num_attacks=6, num_requests=200, num_retries=4, pause_before_retry=3000):
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
        for i in range(num_attacks):
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
    return results


def apply_cidr(company_name):
    """
    Look up the CIDR range for a company's domain name.

    Args:
    - company_name (str): The name of the company's domain name to look up.

    Returns:
    - The CIDR range for the company's domain name as a string.
    - If an exception is raised during the execution of the function, an error message will be returned as a string.
    """
    try:
        # Look up the IP address for the company's domain name
        ip_address = socket.gethostbyname(company_name)

        # Look up the RDAP record for the IP address
        rdap_record = ipwhois.IPWhois(ip_address).lookup_rdap()

        # Extract the CIDR range from the RDAP record
        cidr_range = rdap_record['network']['cidr']

        return cidr_range

    except Exception as e:
        return f"Error: {str(e)}"


def ssh_logger(host, username, password):
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