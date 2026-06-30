from setuptools import setup, find_packages

setup(
    name="Phishing-email-Analyzer",
    version="1.0",
    description="Static analysis + threat-intel verification tool for detecting phishing in raw emails",
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    python_requires=">=3.10",
    install_requires=[
        "requests>=2.31.0",
        "rich>=13.7.0",
        "python-dotenv>=1.0.0",
    ],
    entry_points={
        "console_scripts": [
            "email-forensics=email_forensics.cli:run",
        ],
    },
)
