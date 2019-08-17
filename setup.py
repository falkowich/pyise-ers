from setuptools import find_packages, setup


setup(
    name='ISE',
    version='1.0.0',
    url='',
    license='LICENSE.md',
    maintainer='Jonathan Karras',
    maintainer_email='jonathankarras@weber.edu',
    description='',
    long_description='README.md',
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
