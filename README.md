# Domain Connectivity Testing Tool

A Python script to test connectivity from internal networks to HPE Aruba Networking domains and generate comprehensive reports.

## Overview

This tool tests TCP/HTTP connectivity to a list of domains and ports, helping network administrators identify which external domains are reachable from their internal network. Originally designed for testing HPE Aruba Networking Central domains, it can be adapted for any domain list.

## Features

- ✅ Concurrent domain testing for faster results
- ✅ DNS resolution verification
- ✅ TCP/HTTP/HTTPS connectivity testing
- ✅ Comprehensive CSV reporting
- ✅ Failed domains identification
- ✅ Progress tracking and real-time status
- ✅ Configurable timeouts and concurrency
- ✅ Support for multiple protocols (TCP, HTTP, HTTPS, SSH, UDP, ICMP)

## Requirements

- Python 3.6 or higher
- Required packages: `requests`

## Installation

1. Clone this repository:
```bash
git clone <your-repository-url>
cd domain-connectivity-tester
