from setuptools import setup
import sys
import pip
import os

with open(os.path.join(os.path.dirname(__file__), '__init__.py')) as version_file:
    exec(version_file.read())

if sys.version_info < (3, 6, 3):
    sys.exit("Sorry, you need Python 3.6.3+")

pip_version = int(pip.__version__.replace(".", ""))
if pip_version < 901:
        sys.exit("Sorry, you need pip 9.0.1+")

setup(
    name='magen_ingestion_service',
    version=__version__,
    install_requires=[
        'aniso8601>=1.2.1',
        'coverage>=4.4.1',
        'flake8>=3.3.0',
        'Flask>=0.12.2',
        'Flask-Cors>=3.0.3',
        'lxml>=4.1.0',
        'pycrypto>=2.6.1',
        'pymongo>=3.4.0',
        'pytest>=3.3.1',
        'requests>=2.13.0',
        'responses>=0.5.1',
        'Sphinx>=1.6.3',
        'wheel>=0.30.0a0',
        'magen_logger>=1.0a1',
        'magen_utils>=1.2a2',
        'magen_mongo>=1.0a1',
        'magen_rest_service>=1.2a4',
        'magen_statistics_service>=1.1a1'
      ],
    scripts=['ingestion_server/ingestion_server.py'],
    package_dir={'': '..'},
    packages={'ingestion','ingestion.ingestion_apis','ingestion.ingestion_server','ingestion.ingestion_mongo_apis'},
    include_package_data=True,
    package_data={
        # If any package contains *.txt or *.rst files, include them:
        '': ['*.txt', '*.rst']
    },
    test_suite='tests',
    url='',
    license='Apache',
    author='Reinaldo Penno',
    author_email='rapenno@gmail.com',
    description='Ingestion MicroService Package',
    classifiers=[
        # How mature is this project? Common values are
        #   3 - Alpha
        #   4 - Beta
        #   5 - Production/Stable
        'Development Status :: 2 - Pre-Alpha',

        # Indicate who your project is intended for
        'Intended Audience :: Education',
        'Intended Audience :: Financial and Insurance Industry',
        'Intended Audience :: Healthcare Industry',
        'Intended Audience :: Legal Industry',
        'Topic :: Security',

        # Pick your license as you wish (should match "license" above)
        'License :: Apache',

        # Specify the Python versions you support here. In particular, ensure
        # that you indicate whether you support Python 2, Python 3 or both.
        'Programming Language :: Python :: 3.6',
    ],
)
