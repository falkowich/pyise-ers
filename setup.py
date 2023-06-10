# read the contents of your README file
from os import path

from setuptools import find_packages, setup

this_directory = path.abspath(path.dirname(__file__))
with open(path.join(this_directory, "README.md"), encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="pyise-ers",
    version="0.3.0",
    py_modules=["pyiseers"],
    url="https://github.com/falkowich/pyise-ers",
    download_url="https://pypi.python.org/pypi/pyise-ers",
    license="LICENSE.md",
    maintainer="Andreas Falk",
    maintainer_email="falk@sadsloth.net",
    description="Python wrapper for Cisco ISE ERS API",
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=find_packages(),
    python_requires=">=3.8",
    include_package_data=True,
    zip_safe=False,
    install_requires=["furl>=2.1.3", "requests>=2.30.0", ""],
    extras_require={
        "test": ["pytest", "coverage"],
    },
)
