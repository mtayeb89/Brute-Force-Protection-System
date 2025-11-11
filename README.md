Brute Force Protection System 🛡️
A lightweight, in-memory rate limiter designed to protect authentication endpoints from brute force attacks. This Python library provides an easy-to-use solution for tracking and limiting failed login attempts.
🌟 Features

Rate Limiting: Configurable maximum attempts and lockout duration
Time-Window Based: Only counts recent attempts within a sliding time window
Automatic Cleanup: Old attempts are automatically removed from memory
Flexible Identification: Can track by IP address, username, or any unique identifier
Zero Dependencies: Pure Python implementation with no external libraries required
Memory Efficient: Automatically purges expired attempt records
Multi-Factor Protection: Built-in support for tracking both IP and username
Easy Integration: Works with Flask, Django, FastAPI, and any Python web framework
