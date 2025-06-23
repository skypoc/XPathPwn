from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="xpathpwn",
    version="2.0.2024",
    author="Skyfox",
    author_email="",
    description="Advanced XPath Injection Exploitation Tool",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/skyfox-arch/xpathpwn",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "Topic :: Security",
        "Topic :: Internet :: WWW/HTTP",
    ],
    python_requires=">=3.7",
    install_requires=[
        "aiohttp>=3.8.0",
        "colorama>=0.4.4",
    ],
    entry_points={
        "console_scripts": [
            "xpathpwn=xpathpwn:main",
        ],
    },
    keywords="xpath injection security penetration-testing vulnerability scanner",
    project_urls={
        "Bug Reports": "https://github.com/skyfox-arch/xpathpwn/issues",
        "Source": "https://github.com/skyfox-arch/xpathpwn",
    },
)
