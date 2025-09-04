#!/usr/bin/env python3

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="wordlist3r",
    version="1.0.0",
    author="Wareeq Shile",
    author_email="wareeqshile@protonmail.com",
    description="Fast and intelligent wordlist generator for directory fuzzing",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/wareeqshile/wordlist3r",
    project_urls={
        "Homepage": "https://www.wareeqshile.com",
        "Bug Tracker": "https://github.com/wareeqshile/wordlist3r/issues",
        "Documentation": "https://github.com/wareeqshile/wordlist3r#readme",
        "Source Code": "https://github.com/wareeqshile/wordlist3r",
        "Author Website": "https://www.wareeqshile.com",
        "Twitter": "https://twitter.com/wareeq_shile",
    },
    packages=find_packages(),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: Software Development :: Testing",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: OS Independent",
        "Environment :: Console",
    ],
    python_requires=">=3.7",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "wordlist3r=wordlist3r.main:main",
        ],
    },
    keywords=[
        "wordlist", "directory", "fuzzing", "brute-force", "pentesting", 
        "bug-bounty", "reconnaissance", "security", "web-security"
    ],
    include_package_data=True,
    zip_safe=False,
)
