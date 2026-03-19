from setuptools import setup, find_packages
setup(
    name="lightscan",
    version="2.0.0",
    description="LightScan v2.0 PHANTOM — Async Network Recon & Attack Framework",
    author="Light",
    packages=find_packages(),
    python_requires=">=3.10",
    entry_points={"console_scripts": ["lightscan=lightscan.cli:main"]},
    install_requires=[],  # zero hard deps — optional: paramiko pymysql psycopg2-binary ldap3 impacket
)
