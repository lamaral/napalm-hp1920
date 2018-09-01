"""setup.py file."""

import uuid

from setuptools import setup, find_packages
try: # for pip >= 10
    from pip._internal.req import parse_requirements
except ImportError: # for pip <= 9.0.3
    from pip.req import parse_requirements

__author__ = 'Luiz Amaral <email@luiz.eng.br>'

install_reqs = parse_requirements('requirements.txt', session=uuid.uuid1())
reqs = [str(ir.req) for ir in install_reqs]

setup(
    name="napalm-hp1920",
    version="0.1.0",
    packages=find_packages(),
    author="Luiz Amaral",
    author_email="email@luiz.eng.br",
    description="NAPALM Driver for HPE OfficeConnect 1920",
    classifiers=[
        'Topic :: Utilities',
         'Programming Language :: Python',
         'Programming Language :: Python :: 2',
         'Programming Language :: Python :: 2.7',
        'Operating System :: POSIX :: Linux',
        'Operating System :: MacOS',
    ],
    url="https://github.com/lamaral/napalm-hp1920",
    include_package_data=True,
    install_requires=reqs,
)
