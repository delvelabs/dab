from setuptools import setup, find_packages

__version__ = "0.0.0"


setup(
    name='dab',
    url="https://github.com/delvelabs/dab",
    version=__version__,
    packages=find_packages(),
    entry_points={
        'console_scripts': [
            'dab = dab.__main__:main'
        ]
    },
    install_requires=[
        'aiodns>=2.0.0,<3.0',
        'async_timeout>=3.0.0,<4.0.0',
    ],
)
