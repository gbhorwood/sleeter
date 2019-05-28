# -*- coding: utf-8 -*-

import re
import os
from setuptools import setup


###
# configurations
#
project = "sleeter"
author = "grant horwood"
author_email = "ghorwood@cloverhitch.ca"
project_url = "https://github.com/gbhorwood/sleeter"
description = ""
python_requires = ">=3.7"


###
# get version number using regex from the file
#
version = re.search(
    '^__version__\s*=\s*"(.*)"',
    open(project+'/'+project+'.py').read(),
    re.M
    ).group(1)


###
# Get the contents of README for the long description
#
with open("README.rst", "rb") as f:
    long_description = f.read().decode("utf-8")


###
# get install_requires data from requirements.txt
#
requirements_txt_path = str(os.path.dirname(os.path.realpath(__file__)))+'/'+project+'/requirements.txt'
install_requires = []
if os.path.isfile(requirements_txt_path):
    with open(requirements_txt_path) as f:
        install_requires = f.read().splitlines()


###
# run setup()
#
setup(
    name=project,
    packages=[project],
    entry_points={
        "console_scripts": [project+' = '+project+'.'+project+':main']
        },
    version=version,
    python_requires=python_requires,
    install_requires=install_requires,
    author=author,
    author_email=author_email,
    description=description,
    long_description=long_description,
    url=project_url
)
