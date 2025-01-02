from setuptools import setup

setup(
    name='meowcrypto',
    version='1.0',
    py_modules=['meow'],
    install_requires=[
        'pycryptodome',
    ],
    entry_points={
        'console_scripts': [
            'meow=meow:main',  # Menyambungkan fungsi utama ke perintah terminal
        ],
    },
)
