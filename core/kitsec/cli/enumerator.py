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

import os
import requests
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor

def apply_enumerator(domain, path='lists/active_enumerator', max_workers=10):
    subdomains = set()

    # Find the directory of the current script
    current_script_dir = os.path.dirname(os.path.abspath(__file__))

    # Construct the path to the subdomain list
    path = os.path.join(current_script_dir, '..', path)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        if os.path.isdir(path):
            # If the path is a directory, iterate through each file in the directory
            futures = []
            for filename in os.listdir(path):
                filepath = os.path.join(path, filename)
                if os.path.isfile(filepath):
                    # If the file is a regular file, read each line in the file and send a request to the URL
                    with open(filepath) as f:
                        file_formats = f.read().splitlines()
                        progress_bar = tqdm(file_formats, desc=os.path.splitext(filename)[0], position=0, leave=True)
                        for file_format in progress_bar:
                            full_domain = f"{file_format}.{domain}"
                            future = executor.submit(send_head_request, full_domain)
                            futures.append(future)

            for future in futures:
                result = future.result()
                if result is not None:
                    subdomains.add(result)

        else:
            print(f"{path} does not exist")

    if subdomains:
        return subdomains
    else:
        return set()

def send_head_request(full_domain):
    try:
        # Send a HEAD request to check if the subdomain is active
        response = requests.head("https://" + full_domain, timeout=3)
        if response.status_code < 400:
            return full_domain.split('.')[0]

    except:
        pass

    return None