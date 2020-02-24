from setuptools import find_packages, setup

with open('README.md') as readme_file:
    readme = readme_file.read()


setup(
    name='ISE',
    version='1.1.0',
    py_modules=['ise'],
    url='https://github.com/falkowich/ise',
    download_url='https://pypi.python.org/pypi/ise',
    license='LICENSE.md',
    maintainer='Jonathan Karras',
    maintainer_email='jonathankarras@weber.edu',
    description='API wrapper for ISE',
    long_description=readme,
    packages=find_packages(),
    include_package_data=True,
    zip_safe=False,
    install_requires=[
        'furl>=1.2.1',
        'requests>=2.18.4'
    ],
    extras_require={
        'test': [
            'pytest',
            'coverage'
        ],
    },
)
