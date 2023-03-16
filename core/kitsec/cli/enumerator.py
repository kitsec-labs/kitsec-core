# Standard library modules
from concurrent.futures import ThreadPoolExecutor, as_completed
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
            output = subprocess.check_output(
                ['subfinder', '-d', domain], stderr=nullfile)
        subdomains.update(output.decode('utf-8').strip().split('\n'))
    except BaseException:
        print('Subfinder is not installed or encountered an error, skipping..."')

    # Enumerate using Amass
    try:
        print('Enumerating using Amass...')
        with open(os.devnull, 'w') as nullfile:
            output = subprocess.check_output(
                ['amass', 'enum', '--passive', '-d', domain], stderr=nullfile)
        subdomains.update([s.split(
            '.')[0] + '.' + domain for s in output.decode('utf-8').strip().split('\n')])
    except BaseException:
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


def fetch_response_worker(
        subdomain: str,
        session: requests.Session) -> List[str]:
    try:
        response = session.get(f'http://{subdomain}', timeout=5)
        return [subdomain, response.status_code, response.reason, '']
    except requests.exceptions.Timeout:
        print(f"Skipped '{subdomain}'")
    except requests.exceptions.ConnectionError:
        print(f"Skipped '{subdomain}'")
    except Exception as e:
        print(f"Skipped '{subdomain}': {str(e)}")
    return None


def fetch_response(subdomains: List[str],
                   technology: bool,
                   max_workers: int = 10) -> List[List[str]]:
    response_table = []
    session = requests.Session()

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_subdomain = {
            executor.submit(
                fetch_response_worker,
                subdomain,
                session): subdomain for subdomain in subdomains}
        for future in tqdm(
                as_completed(future_to_subdomain),
                desc='Fetching response',
                total=len(subdomains),
                unit='subdomain',
                leave=False):
            result = future.result()
            if result:
                response_table.append(result)
            time.sleep(0.5)

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
    warnings.filterwarnings(
        "ignore",
        category=UserWarning,
        message=".*It looks like you're parsing an XML document using an HTML parser.*")
    warnings.filterwarnings(
        "ignore",
        message="""Caught 'unbalanced parenthesis at position 119' compiling regex""",
        category=UserWarning)

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


def apply_enumerator(request, technology, domain):
    """
    Enumerates subdomains for a given domain using passive enumeration.
    """
    # Get subdomains using passive enumeration
    subdomains = passive_enumerator(domain)

    if request and not technology:
        # Test subdomains and print http response for active ones
        response_table = fetch_response(subdomains, False)
        # sort response_table by status in ascending order
        response_table = sorted(response_table, key=lambda x: x[1])
        click.echo(
            tabulate(
                response_table,
                headers=[
                    'Subdomain',
                    'Status',
                    'Reason']))

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
        response_df = pd.DataFrame(
            response_table,
            columns=[
                'Subdomain',
                'Status',
                'Reason',
                'Technology'])
        tech_df = pd.DataFrame(tech_table, columns=['Subdomain', 'Technology'])
        combined_df = pd.merge(
            response_df,
            tech_df,
            on='Subdomain',
            how='outer')
        # replace NaN values with empty string
        combined_df.fillna('', inplace=True)
        combined_table = combined_df.to_records(index=False).tolist()

        click.echo(
            tabulate(
                combined_table,
                headers=[
                    'Subdomain',
                    'Status',
                    'Reason',
                    'Technology']))

    if not request and not technology:
        # Just print the subdomains
        subdomains_list = list(subdomains)
        with tqdm(total=len(subdomains_list), desc='Enumerating subdomains', unit='subdomain') as pbar:
            subdomains_list = [[subdomain] for subdomain in subdomains_list]
            click.echo(tabulate(subdomains_list, headers=['Subdomain']))
            pbar.update(len(subdomains_list))
