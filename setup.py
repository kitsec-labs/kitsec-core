from setuptools import setup, find_packages

setup(
    name='kitsec',
    version='0.1',
    py_modules=['kitsec'],
    install_requires=[
        'Click',
        'requests',
        'paramiko',
        'tqdm',
        'bs4',
        'tabulate',
        'Wappalyzer',
    ],
    entry_points='''
        [console_scripts]
        kitsec=kitsec:cli
    ''',
)