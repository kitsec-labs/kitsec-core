# Third-party modules
import requests
from bs4 import BeautifulSoup



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


def query_cve(product_name, limit=10):
    """
    Retrieves CVE data for a specific product name and displays it in a clean format.

    Args:
        - product_name (str): The product name (company name) to search for.

    Options:
        - limit (int): Number of results to display (default=10).

    Returns:
        - str: A plain string with each CVE record separated by a newline.
    """
    # Make request to the NVD API and extract relevant fields
    url = f"https://services.nvd.nist.gov/rest/json/cves/1.0?keyword={product_name}&resultsPerPage={limit}"
    response = requests.get(url)
    data = response.json()
    cve_items = data.get("result", {}).get("CVE_Items", [])

    # Prepare the data to be displayed in a plain string format
    result = ""
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
            result += f"CVE ID: {cve_id}\nCWE: {cwe_name}\nSeverity: {severity_msg}\nSummary: {summary}\n\n"

    return result