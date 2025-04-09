# KMN Vulnerability Scanner

A comprehensive vulnerability scanning tool that combines port scanning, network discovery, and vulnerability detection capabilities.

## Table of Contents
- [Features](#features)
- [Installation](#installation)
  - [Standard Installation](#standard-installation)
  - [Docker Installation](#docker-installation)
  - [Platform-Specific Guides](#platform-specific-guides)
- [Usage](#usage)
  - [Management Script](#management-script)
  - [Port Scanning](#1-port-scanning)
  - [Network Discovery](#2-network-discovery)
  - [Vulnerability Search](#3-vulnerability-search)
  - [Database Management](#4-database-management)
  - [Web Interface](#web-interface)
- [Database Structure](#database-structure)
- [Development Setup](#development-setup)
- [Security Considerations](#security-considerations)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)
- [Command Line Usage Examples](#command-line-usage-examples)

## Features

### 1. Port Scanning
- Discover open ports on target systems
- Service version detection
- Results stored in SQLite database
- No root privileges required (except for SYN scan)
- Progress tracking and formatted output
- Support for TCP Connect and SYN scan types

### 2. Network Discovery
- Automatic network class detection (A, B, C)
- Ping sweep to find active hosts
- Concurrent scanning with configurable workers
- Hostname resolution
- Results stored in SQLite database
- Efficient and fast network mapping

### 3. Vulnerability Scanning
- Advanced vulnerability detection using Nmap scripts
- Detection of common vulnerabilities like:
  - MS17-010 (EternalBlue)
  - SMB vulnerabilities
  - Service-specific vulnerabilities
- Detailed vulnerability reports with:
  - Vulnerability state and risk level
  - CVE IDs and references
  - Technical descriptions
- Real-time scan progress tracking
- Results displayed in an easy-to-read format

### 4. Web Interface
- Modern and responsive design
- Real-time scan progress updates
- Interactive port scanning interface
- Network discovery visualization
- Vulnerability scanning for specific ports
- Search and filter vulnerability database
- Scan history and results management

## Installation

### Standard Installation

1. Clone the repository:
```bash
git clone https://github.com/KhitMinnyo/KMN-V-Scanner.git
cd KMN-V-Scanner
```

2. Create a virtual environment and install dependencies:
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: .\venv\Scripts\activate
pip install -r requirements.txt
```

3. Install nmap:
```bash
# Ubuntu/Debian
# If Kali Linux & Parrot Security OS , skip this .
sudo apt install nmap -y

# CentOS/RHEL
sudo yum install nmap

# macOS
brew install nmap

# Windows
# Download and install from https://nmap.org/download.html
```

4. Set up environment variables:
```bash
source venv/bin/activate 
# Edit .env and add your NVD API key from https://nvd.nist.gov/developers/request-an-api-key
```

### Docker Installation

1. Install Docker and Docker Compose for your platform:
   - [Docker Installation Guide](https://docs.docker.com/get-docker/)
   - [Docker Compose Installation Guide](https://docs.docker.com/compose/install/)

2. Clone and configure:
```bash
# Clone repository
git clone https://github.com/yourusername/KMN-V-Scanner.git
cd KMN-V-Scanner

# Configure environment
cp .env.example .env
# Edit .env and add your NVD API key
```

3. Build and run with Docker:
```bash
# Start the container
docker-compose up -d

# View logs
docker-compose logs -f
```

The web interface will be available at: http://localhost:2025

#### Docker Commands Reference
```bash
# Stop the container
docker-compose down

# Restart the container
docker-compose restart

# Rebuild after changes
docker-compose up -d --build

# Execute commands in container
docker-compose exec vulnerability-scanner ./manage.sh [command]

# View container status
docker-compose ps
```

### Platform-Specific Guides

- **Kali Linux**: See [kali.md](kali.md) for detailed Kali Linux installation instructions
- **Windows**: Standard and Docker installation supported
- **macOS**: Standard and Docker installation supported
- **Ubuntu/Debian**: Standard and Docker installation supported

## Usage

### Management Script
The `manage.sh` script provides easy access to all features:

```bash
./manage.sh [command] [options]
```

Available commands:
- `clean` - Clean all databases
- `download` - Download vulnerabilities from NVD
- `run` - Run the web application
- `scan` - Run port scan and service detection
- `discover` - Discover active hosts in local network
- `help` - Show help message

### 1. Port Scanning
Scan ports on a target system:

```bash
# Scan all ports
./manage.sh scan example.com

# Scan specific port range
./manage.sh scan example.com --start-port 80 --end-port 443

# SYN scan (requires root)
sudo ./manage.sh scan example.com --scan-type SYN

# Aggressive scan with service detection
sudo ./manage.sh scan example.com --aggressive
```

Features:
- TCP connect scan (no root required)
- SYN scan (requires root)
- Service version detection
- Progress tracking
- Results saved to `data/portscan.db`

### 2. Network Discovery
Discover active hosts in a local network:

```bash
# Discover hosts in network
./manage.sh discover 192.168.1.1

# Adjust concurrent workers
./manage.sh discover 192.168.1.1 --max-workers 100
```

Features:
- Automatic network class detection
- Concurrent ping sweep
- Hostname resolution
- Results saved to `data/network.db`

### 3. Vulnerability Search
Run the web interface to search vulnerabilities:

```bash
./manage.sh run
#OR
python app.py 
#OR
python3 app.py 
```

Then visit: http://localhost:2025

Web Interface Features:
- Modern and responsive UI
- Advanced search functionality
  - Search by keywords
  - Filter by vendors/products
  - Filter by severity
  - Filter by date range
- Detailed vulnerability information
  - CVE details
  - CVSS scores
  - Affected products
  - References
- Export results to CSV
- Regular database updates

### 4. Database Management
Clean and update databases:

```bash
# Clean all databases
./manage.sh clean

# Download fresh vulnerability data
./manage.sh download
```

### Run as Web Interface (Recommended)

1. Start the web server:
```bash
source venv/bin/activate
python app.py
```

2. Access the web interface at: http://localhost:2025

3. Features:
   - **Port Scanning**: Scan target systems for open ports
   - **Network Discovery**: Find active hosts in your network
   - **Vulnerability Scanning**: Check for known vulnerabilities
   - **Vulnerability Database**: Search CVE database

## Database Structure

### 1. Vulnerability Database (vuln.db)
- Stores CVE data from NVD
- Includes descriptions, severity, and affected products
- Updated via NVD API
- SQLite format for portability

### 2. Port Scan Database (portscan.db)
- Stores port scan results
- Records open ports and service versions
- Tracks scan timestamps
- Includes scan configuration details

### 3. Network Database (network.db)
- Stores network discovery results
- Records active hosts and hostnames
- Includes network class information
- Tracks discovery timestamps

## Development Setup

1. Install development dependencies:
```bash
pip install -r requirements-dev.txt  # If exists
```

2. Set up pre-commit hooks:
```bash
pre-commit install  # If using pre-commit
```

3. Run tests:
```bash
python -m pytest tests/  # If tests exist
```

## Security Considerations

1. API Key Protection:
   - Store NVD API key securely in `.env`
   - Never commit `.env` file to version control
   - Use environment variables in production

2. Scanning Permissions:
   - SYN scans require root privileges
   - Regular TCP scans can run as non-root
   - Be cautious when scanning networks you don't own

3. Rate Limiting:
   - Respect NVD API rate limits
   - Implement reasonable delays between scans
   - Use concurrent workers responsibly

## Troubleshooting

1. Permission Issues:
   - Ensure proper permissions for database directory
   - Run with sudo for SYN scans
   - Check file ownership in data directory

2. Network Issues:
   - Verify network connectivity
   - Check firewall settings
   - Ensure proper routing for target networks

3. Database Issues:
   - Run `./manage.sh clean` to reset databases
   - Verify disk space availability
   - Check database file permissions

## Contributing
Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

## Command Line Usage Examples
```bash
# Actually, you may not need to use command line

# Network Discovery
./manage.sh discover 172.20.10.1
./manage.sh discover 192.168.1.1 --max-workers 100

# Port Scanning
./manage.sh scan example.com --start-port 80 --end-port 443
./manage.sh scan google.com --start-port 80 --end-port 443
sudo ./manage.sh scan localhost --scan-type SYN --aggressive
sudo ./manage.sh scan localhost --start-port 1 --end-port 1000 --scan-type TCP
