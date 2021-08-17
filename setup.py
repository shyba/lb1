from setuptools import setup
from setuptools_rust import RustExtension


setup(
    name="lb1-miner",
    version="0.1.0",
    classifiers=[
        "License :: OSI Approved :: MIT License",
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Programming Language :: Python",
        "Programming Language :: Rust",
    ],
    packages=["lb1miner"],
    include_package_data=True,
    rust_extensions=[RustExtension("lb1ext.lb1ext", "Cargo.toml", debug=False)],
    install_requires=[
        'aiorpcX==0.18.7'
    ],
    zip_safe=False,
)
