import os
import sys

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

# PYPI UPLOAD METHOD:
# python setup.py sdist

long_description = '''
Eloqua Python SDK wrapping Eloqua Rest API and Eloqua BULK API.
'''

setup(
    name='eloqua-python-sdk',
    version= '0.1',
	url='https://source.developers.google.com/p/eloquamart/r/eloqua-python-sdk',
    author='Ignotas Petrulis',
    author_email='ignotas.petrulis@gmail.com',
    packages=['bulk', 'rest'],
    install_requires=[
        'requests'
    ],
    keywords = ['Eloqua', 'BULK API' 'REST API'],
    description='Eloqua Python SDK',
    long_description=long_description
)