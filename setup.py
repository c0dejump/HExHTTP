# Author:
# Nathan Faillenot (codejump - @c0dejump)

import pathlib
import setuptools
from setuptools import setup, find_packages, Extension

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="HExHTTP",
    version="2.0",
    author="c0dejump",
    author_email="codejumpgame@gmail.com",
    description="HExHTTP is a tool designed to perform tests on HTTP headers and analyze the results to identify vulnerabilities and interesting behaviors.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=find_packages(exclude=["static"]),
    include_package_data=True,
    url="https://github.com/c0dejump/HExHTTP/",
    install_requires=[
        'requests==2.31.0',
        'wafw00f==2.2.0',
        'urllib3==2.2.1',
        'notify-py==0.3.42',
        'pync==2.0.3',
        'bs4',
        'httpx'
    ],
    project_urls={
        "Bug Tracker": "https://github.com/c0dejump/HExHTTP/issues",
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)