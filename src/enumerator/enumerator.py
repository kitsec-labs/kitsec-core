# Standard library modules
import os
import subprocess
import time
from typing import List

# Third-party modules
import click
import pandas as pd
import requests
import warnings
from tabulate import tabulate
from tqdm import tqdm
from urllib.parse import urlparse
from Wappalyzer import Wappalyzer, WebPage


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

    # Enumerate using Amass
    try:
        print('Enumerating using Amass...')
        with open(os.devnull, 'w') as nullfile:
            output = subprocess.check_output(['amass', 'enum', '--passive', '-d', domain], stderr=nullfile)
        subdomains.update([s.split('.')[0] + '.' + domain for s in output.decode('utf-8').strip().split('\n')])
    except:
        print('Amass is not installed or encountered an error, skipping... / debug by running "amass enum --passive -d example.com"')

    # Enumerate using Findomain
#    try:
#        print('Enumerating using Findomain...')
#        with open(os.devnull, 'w') as nullfile:
#            output = subprocess.check_output(['findomain', '-t', domain], stderr=nullfile)
#        subdomains.update(output.decode('utf-8').strip().split('\n')[1:])
#        subdomains = set([x for x in subdomains if domain in x])
#    except:
#        print('Findomain is not installed or encountered an error, skipping..."')

    # Enumerate using waybackurls
#    try:
#        print('Enumerating using waybackurls...')
#        with open(os.devnull, 'w') as nullfile:
#            output = subprocess.check_output(['waybackurls', domain], stderr=nullfile)
#        subdomains.update([urlparse(url).hostname for url in output.decode('utf-8').strip().split('\n')])
#    except:
#        print('waybackurls is not installed or encountered an error, skipping... / debug by running "waybackurls example.com"')

    # Enumerate using Assetfinder
#    try:
#        print('Enumerating using Assetfinder...')
#        with open(os.devnull, 'w') as nullfile:
#            output = subprocess.check_output(['assetfinder', '--subs-only', domain], stderr=nullfile)
#        subdomains.update([s.split('.')[0] for s in output.decode('utf-8').strip().split('\n')])
#    except:
#        print('Assetfinder is not installed or encountered an error, skipping..."')
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


def apply_enumerator(request, technology, active, domain):
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