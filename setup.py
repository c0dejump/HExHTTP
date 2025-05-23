from setuptools import setup, find_packages

setup(
    name="hexhttp",
    version="1.8",
    description="HExHTTP is a tool designed to perform tests on HTTP headers and analyze the results to identify vulnerabilities and interesting behaviors.",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    author="c0dejump",
    url="https://github.com/c0dejump/HExHTTP",
    license="MIT",
    packages=find_packages(exclude=["tests", "docs"]),
    python_requires=">=3.7",
    install_requires=[
        "requests==2.31.0",
        "wafw00f==2.2.0",
        "urllib3==2.2.1",
        "notify-py==0.3.42",
        "pync==2.0.3",
        "bs4",
        "httpx"
    ],
    entry_points={
        "console_scripts": [
            "hexhttp=hexhttp:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Intended Audience :: Developers",
    ],
    include_package_data=True,
)
