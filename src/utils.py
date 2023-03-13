# Standard library modules
import gzip
import hashlib
import html
import urllib.parse
import paramiko

# Third-party modules
import base64
import magic

def linode_logger(host, username, password, command):
    """
    Connects to a remote server using SSH and executes a command.

    Args:
    - host (str): The IP address or hostname of the remote server.
    - username (str): The username to use for SSH authentication.
    - password (str): The password to use for SSH authentication.
    - command (str): The command to execute on the remote server.

    Returns:
    - The output of the command executed on the remote server.
    """
    client = paramiko.client.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(host, username=username, password=password)
    _stdin, _stdout,_stderr = client.exec_command(command)
    output = _stdout.read().decode()
    client.close()
    return output



def apply_transformation(data, transformation_type):
    """
    Applies a specified decoding or hashing function to input data.

    Args:
    - data (bytes): The input data to be transformed.
    - transformation_type (str): The type of transformation to apply.

    Returns:
    - If the input data is text, the transformed input data as a string.
    - If the input data is binary, the resulting hash as a string.
    - If an invalid transformation type is specified, an error message as a string.
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

    return result