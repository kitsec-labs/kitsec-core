from setuptools import setup, find_packages

setup(
    name='kitsec',
    version='0.1.2',
    description='A package to streamline Ethical hackers workflows',
    author='Idriss CHEBAK',
    author_email='idrisschebak@me.com',
    url='https://github.com/kitsec-labs/kitsec-core',
    packages=find_packages(),
    install_requires=[
        'Pillow',
        'python_wappalyzer==0.3.1',
        'beautifulsoup4==4.11.2',
        'python-magic==0.4.27',
        'cve_search==1.0.11',
        'wappalyzer==1.0.0',
        'ipaddress==1.0.23',
        'termcolor==2.2.0',
        'requests==2.28.1',
        'paramiko==3.0.0',
        'tabulate==0.9.0',
        'ipwhois==1.2.0',
        'pandas==1.2.5',
        'click==7.1.2',
        'tqdm==4.64.1',
        'nmap==0.0.1',
        'bs4==0.0.1'
    ],
    entry_points='''
        [console_scripts]
        kitsec=kitsec:cli
    ''',
    filename='kitsec-0.1.1.tar.gz'
)