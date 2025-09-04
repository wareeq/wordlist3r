"""
wordlist3r - Fast and intelligent wordlist generator for directory fuzzing

Author: Wareeq Shile
Website: https://www.wareeqshile.com
Twitter: @wareeq_shile
Email: wareeqshile@protonmail.com

A powerful Python tool that extracts custom wordlists from live web applications 
by analyzing page content, titles, metadata, and domain structures. Perfect for 
bug bounty hunters and penetration testers who need targeted wordlists for 
directory brute-forcing.
"""

__version__ = "1.0.0"
__author__ = "Wareeq Shile"
__email__ = "wareeqshile@protonmail.com"
__website__ = "https://www.wareeqshile.com"
__twitter__ = "https://twitter.com/wareeq_shile"
__description__ = "Fast and intelligent wordlist generator for directory fuzzing"
__license__ = "MIT"

from .main import main

__all__ = ['main', '__version__', '__author__', '__email__', '__website__', '__twitter__']
