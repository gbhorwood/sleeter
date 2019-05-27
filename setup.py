# -*- coding: utf-8 -*-

import re
import os
from setuptools import setup

###
# get version number using regex from the file
#
version = re.search(
    '^__version__\s*=\s*"(.*)"',
    open('sleeter/sleeter.py').read(),
    re.M
    ).group(1)

###
# get install_requires data from requirements.txt
#
requirements_txt_path = str(os.path.dirname(os.path.realpath(__file__)))+"/requirements.txt"
install_requires = []
if os.path.isfile(requirements_txt_path):
    with open(requirements_txt_path) as f:
        install_requires = f.read().splitlines()


setup (
    name = "sleeter",
    packages = ["sleeter"],
    entry_points = {
        "console_scripts": ['sleeter = sleeter.sleeter:main']
        },
    python_requires=">=3.7",
    install_requires = install_requires,
    author = "grant horwood",
    url = "http://cloverhitch.ca"
)
