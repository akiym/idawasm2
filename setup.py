#!/usr/bin/env python

import setuptools

setuptools.setup(
    name="idawasm2",
    version="0.2.0",
    description="IDA loader and processor for WebAssembly.",
    author="Willi Ballenthin, Takumi Akiyama",
    author_email="william.ballenthin@fireeye.com, t.akiym@gmail.com",
    license="Apache 2.0 License",
    packages=setuptools.find_packages(),
    install_requires=[
        'wasm',
        'ida-netnode',
    ],
)
