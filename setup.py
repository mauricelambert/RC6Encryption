import RC6Encryption as package
from setuptools import setup

setup(
    name=package.__name__,
    version=package.__version__,
    py_modules=[package.__name__],
    install_requires=[],
    author=package.__author__,
    author_email=package.__author_email__,
    maintainer=package.__maintainer__,
    maintainer_email=package.__maintainer_email__,
    description=package.__description__,
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url=package.__url__,
    project_urls={
        "Documentation": "https://mauricelambert.github.io/info/python/security/RC6Encryption.html",
        "Executable": "https://mauricelambert.github.io/info/python/security/RC6Encryption.pyz",
    },
    classifiers=[
        "Topic :: Security",
        "Environment :: Console",
        "Operating System :: MacOS",
        "Natural Language :: English",
        "Programming Language :: Python",
        "Intended Audience :: Developers",
        "Topic :: Security :: Cryptography",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3.9",
        "Operating System :: Microsoft :: Windows",
        "Intended Audience :: System Administrators",
        "Development Status :: 5 - Production/Stable",
        "License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)",
    ],
    entry_points={
        "console_scripts": [
            "rc6 = RC6Encryption:main",
        ],
    },
    python_requires=">=3.8",
    keywords=[
        "RC6",
        "Encryption",
        "Cipher",
    ],
    platforms=["Windows", "Linux", "MacOS"],
    license=package.__license__,
)
