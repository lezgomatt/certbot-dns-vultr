import setuptools

with open("README.md", "r") as readme:
    long_description = readme.read()

setuptools.setup(
    name="certbot-dns-vultr",
    version="0.0.2",
    description="Vultr DNS Authenticator plugin for Certbot",
    url="https://github.com/undecidabot/certbot-dns-vultr",
    author="Matt",
    author_email="undecidabot@gmail.com",
    license="Zlib",
    long_description=long_description,
    long_description_content_type="text/markdown",
    classifiers=[
        "Environment :: Plugins",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: zlib/libpng License",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: Security",
        "Topic :: System :: Installation/Setup",
        "Topic :: System :: Networking",
        "Topic :: System :: Systems Administration",
        "Topic :: Utilities",
    ],
    py_modules=["certbot_dns_vultr"],
    python_requires=">=3.6",
    install_requires=[
        "certbot",
        "requests",
        "zope.interface",
    ],
    entry_points={
        "certbot.plugins": [
            "dns-vultr = certbot_dns_vultr:Authenticator",
        ],
    },
)
