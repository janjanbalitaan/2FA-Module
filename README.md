# 2FA Module

2FA Module allows you to setup two factor authentication for your applications. It is compatible with google authenticator, so you can generate a qr code from the uri returned in this module and scan it with the google authenticator app.

## Requirements
* [Python 3.8.1](https://www.python.org/downloads/release/python-381)
* [Package Manager](https://pip.pypa.io/en/stable/)

## Installation
* Create a virtual environment
```bash
python3 -m venv venv
```
* Enable the virtualenvironment
```bash
source venv/bin/activate
```
* Install libraries
```bash
pip install -r requirements.txt
```

## Usage
* Running the script
```bash
python main.py
```
* Running the test cases
```bash
cd tests
pytest -v test.py 
```