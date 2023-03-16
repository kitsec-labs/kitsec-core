# Standard library modules
import os

# Third-party modules
import click
import requests
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor
import pkg_resources


def send_request(url):
    response = requests.get(url)
    if response.status_code == 200:
        print(f"Found URL with status 200: {url}")


def apply_path_fuzz(base_url, path='lists/fuzz/path_fuzz', max_workers=10):
    if not base_url.startswith('http'):
        base_url = 'http://' + base_url

    # Find the directory of the current script
    current_script_dir = os.path.dirname(os.path.abspath(__file__))

    # Construct the path to the fuzz list
    path = os.path.join(current_script_dir, '..', path)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        if os.path.isdir(path):
            # If the path is a directory, iterate through each file in the
            # directory
            futures = []
            for filename in os.listdir(path):
                filepath = os.path.join(path, filename)
                if os.path.isfile(filepath):
                    # If the file is a regular file, read each line in the file
                    # and send a request to the URL
                    with open(filepath) as f:
                        file_formats = f.read().splitlines()
                        progress_bar = tqdm(
                            file_formats,
                            desc=os.path.splitext(filename)[0],
                            position=0,
                            leave=True)
                        for file_format in progress_bar:
                            url = f"{base_url}/{file_format}"
                            future = executor.submit(send_request, url)
                            futures.append(future)

            for future in futures:
                future.result()

        elif os.path.isfile(path):
            # If the path is a regular file, read each line in the file and
            # send a request to the URL
            with open(path) as f:
                file_formats = f.read().splitlines()
                progress_bar = tqdm(
                    file_formats,
                    desc=os.path.basename(path),
                    position=0,
                    leave=True)
                futures = []
                for file_format in progress_bar:
                    url = f"{base_url}/{file_format}"
                    future = executor.submit(send_request, url)
                    futures.append(future)

                for future in futures:
                    future.result()

        else:
            print(f"{path} does not exist")


def apply_file_format_fuzz(
        base_url,
        path='lists/fuzz/file_fuzz',
        max_workers=10):
    if not base_url.startswith('http'):
        base_url = 'http://' + base_url

    # Find the directory of the current script
    current_script_dir = os.path.dirname(os.path.abspath(__file__))

    # Construct the path to the fuzz list
    path = os.path.join(current_script_dir, '..', path)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        if os.path.isdir(path):
            # If the path is a directory, iterate through each file in the
            # directory
            futures = []
            for filename in os.listdir(path):
                filepath = os.path.join(path, filename)
                if os.path.isfile(filepath):
                    # If the file is a regular file, read each line in the file
                    # and send a request to the URL
                    with open(filepath) as f:
                        file_formats = f.read().splitlines()
                        progress_bar = tqdm(
                            file_formats,
                            desc=os.path.splitext(filename)[0],
                            position=0,
                            leave=True)
                        for file_format in progress_bar:
                            url = f"{base_url}/{file_format}"
                            future = executor.submit(send_request, url)
                            futures.append(future)

            for future in futures:
                future.result()

        elif os.path.isfile(path):
            # If the path is a regular file, read each line in the file and
            # send a request to the URL
            with open(path) as f:
                file_formats = f.read().splitlines()
                progress_bar = tqdm(
                    file_formats,
                    desc=os.path.basename(path),
                    position=0,
                    leave=True)
                futures = []
                for file_format in progress_bar:
                    url = f"{base_url}/{file_format}"
                    future = executor.submit(send_request, url)
                    futures.append(future)

                for future in futures:
                    future.result()

        else:
            print(f"{path} does not exist")
