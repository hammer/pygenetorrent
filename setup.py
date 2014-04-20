from setuptools import setup

setup(
    name='pygenetorrent',
    version='0.1',
    long_description=__doc__,
    scripts=['scripts/gtdownload.py'],
    zip_safe=False,
    install_requires=[
        'BitTorrent-bencode',
        'pkiutils',
        'pycrypto',
        'requests',
    ],
)
