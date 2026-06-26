from setuptools import setup, find_packages

setup(
    name="TRACEX",
    version="1.0.0",
    author="Harilal P",
    author_email="thisisharilal@gmail.com",
    description="Windows Event Log Analyzer — Detection & MITRE ATT&CK Mapping",
    packages=find_packages(),
    py_modules=["main"],
    install_requires=[
        "python-evtx",
        "colorama",
        "pyfiglet",
    ],
    entry_points={
        "console_scripts": [
            "tracex=main:main",
        ],
    },
    python_requires=">=3.10",
)