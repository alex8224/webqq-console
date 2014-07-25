#!/usr/bin/env python
#-*-coding:utf-8 -*-
#
#Author: tony - birdaccp at gmail.com
#Create by:2014-07-25 14:55:43
#Last modified:2014-07-25 17:26:40
#Filename:setup.py
#Description:

from setuptools import setup, find_packages

setup(
        name = 'pywebqq',
        version = '0.2',
        keywords = ('pyqq', 'pywebqq', 'webqq', 'pyweb'),
        license = 'MIT License',
        description = '通过模拟WEBQQ3.0实现的命令行QQ聊天工具',
        author = "alex8224@gmail.com, birdaccp@gmail.com",
        author_email = "alex8224@gmail.com, birdaccp@gmail.com",
        #packages = ['pywebqq'],
        packages = find_packages(),
        #include_package_data = True,
        package_data = {
                '' : ['*.conf', '*.txt'],
            },
        install_requires = [
            'redis>=2.7.6',
            'requests>=2.0.0',
            'gevent>=1.0.0',
            'colorama>=0.3.1'
            ],
        entry_points = {
            'console_scripts':[
                'pywebqq.server=pywebqq.webqq:main',
                'pywebqq.client=pywebqq.client:main',
                ],
            },
        url = "http://github.com/ftfniqpl/webqq-console",
        platforms = 'any',
        classifiers=[
            'License :: OSI Approved :: MIT License',
            'Programming Language :: Python :: 2',
            'Programming Language :: Python :: 2.6',
            'Programming Language :: Python :: 2.7',
            'Topic :: Utilities',
        ],
        long_description = "Use the command-line version of python implementation WEBQQ"
    )
