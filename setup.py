from setuptools import find_packages, setup

"""
THIS IS A STUB FOR RUNNING THE APP
"""

# APP = ['instant_withdrawal/sign.py']

setup(
    # app=APP,
    name="instant_withdrawal",
    version='1.0.0',
    py_modules=["instant_withdrawal"],
    packages=find_packages(exclude=('tests', 'docs')),
    python_requires=">=3.8,<4",
)
