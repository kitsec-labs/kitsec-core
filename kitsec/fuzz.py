# Standard library modules
import os
import threading
from concurrent.futures import ThreadPoolExecutor


# Third-party modules
import click
import requests
from tqdm import tqdm


def send_request(url):
    response = requests.get(url)
    if response.status_code == 200:
        click.echo(f"{url} - {response.status_code}")


def apply_path_fuzz(base_url, path='../lists/fuzz/path_fuzz'):
    """
    Sends HTTP GET requests to a specified base URL with a given list of paths.

    Args:
    - base_url (str): The base URL to send requests to. The URL must include the protocol (http or https).

    Options:
    - path (str): The path to a file or directory containing a list of paths to send requests to. Default: ../lists/fuzz/path_fuzz

    Returns:
    - None. For each request sent, the program will print the URL and response code to the console if the response code is 200.
    """
    # Add http or https prefix if missing
    if not base_url.startswith('http'):
        base_url = 'http://' + base_url

    # Check if the path exists
    if not os.path.exists(path):
        # If the path does not exist, print an error message to the console
        click.echo(f"{path} does not exist")
        return

    # If the path is a file, read each line in the file and create a request for each line
    if os.path.isfile(path):
        with open(path) as f:
            paths = f.read().splitlines()
            with ThreadPoolExecutor() as executor:
                futures = []
                for p in paths:
                    url = f"{base_url}/{p}"
                    futures.append(executor.submit(send_request, url))

                for future in tqdm(futures, desc=os.path.basename(path), position=0, leave=True):
                    future.result()

    # If the path is a directory, iterate through each file in the directory
    elif os.path.isdir(path):
        with ThreadPoolExecutor() as executor:
            futures = []
            for filename in os.listdir(path):
                filepath = os.path.join(path, filename)
                if os.path.isfile(filepath):
                    with open(filepath) as f:
                        paths = f.read().splitlines()
                        for p in paths:
                            url = f"{base_url}/{p}"
                            futures.append(executor.submit(send_request, url))

            for future in tqdm(futures, desc="File path fuzz", position=0, leave=True):
                future.result()


def apply_file_format_fuzz(base_url, path='../lists/fuzz/file_fuzz'):
    """
    Sends HTTP GET requests to a specified base URL with a given list of file formats.

    Args:
    - base_url (str): The base URL to send requests to. The URL must include the protocol (http or https).

    Options:
    - path (str): The path to a file or directory containing a list of file formats to send requests to. Default: ../lists/fuzz/file_fuzz

    Returns:
    - None. For each request sent, the program will print the URL and response code to the console if the response code is 200.
    """
    # Add http or https prefix if missing
    if not base_url.startswith('http'):
        base_url = 'http://' + base_url

    # Check if the path is a directory or a file
    if os.path.isdir(path):
        # If the path is a directory, iterate through each file in the directory
        with ThreadPoolExecutor() as executor:
            futures = []
            for filename in os.listdir(path):
                filepath = os.path.join(path, filename)
                if os.path.isfile(filepath):
                    # If the file is a regular file, read each line in the file and create a request for each line
                    with open(filepath) as f:
                        file_formats = f.read().splitlines()
                        for file_format in file_formats:
                            url = f"{base_url}/{file_format}"
                            futures.append(executor.submit(send_request, url))

            for future in tqdm(futures, desc="File format fuzz", position=0, leave=True):
                future.result()

    elif os.path.isfile(path):
        # If the path is a regular file, read each line in the file and create a request for each line
        with open(path) as f:
            file_formats = f.read().splitlines()
            with ThreadPoolExecutor() as executor:
                futures = []
                for file_format in file_formats:
                    url = f"{base_url}/{file_format}"
                    futures.append(executor.submit(send_request, url))

                for future in tqdm(futures, desc=os.path.basename(path), position=0, leave=True):
                    future.result()

    else:
        # If the path does not exist, print an error message to the console
        click.echo(f"{path} does not exist")