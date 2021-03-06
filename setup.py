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
    version='0.2.3',
    url='https://github.com/ignotas-petrulis/eloqua-python-sdk.git',
    author='Ignotas Petrulis',
    author_email='ignotas.petrulis@gmail.com',
    packages=['eloquasdk'],
    install_requires=[
        'requests'
    ],
    description='Eloqua Python SDK',
    long_description=long_description
)
