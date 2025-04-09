# Installing KMN Vulnerability Scanner on Kali Linux

This guide provides detailed instructions for installing and setting up KMN Vulnerability Scanner on Kali Linux.

## Installation Methods
- [Standard Installation](#installation-steps)
- [Docker Installation](#docker-installation)

## System Requirements
- Kali Linux (Latest Version)
- Python 3.x (Pre-installed on Kali)
- Git (Pre-installed on Kali)
- Nmap (Pre-installed on Kali)

## Installation Steps

1. **Clone the Repository**
   ```bash
   git clone https://github.com/yourusername/KMN-V-Scanner.git
   cd KMN-V-Scanner
   ```

2. **Set Up Python Virtual Environment**
   ```bash
   # Install python3-venv if not already installed
   sudo apt update
   sudo apt install python3-venv -y

   # Create and activate virtual environment
   python3 -m venv venv
   source venv/bin/activate
   ```

3. **Install Required Python Packages**
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure Environment Variables**
   ```bash
   # Copy example environment file
   cp .env.example .env

   # Edit the .env file with your preferred editor
   nano .env
   ```
   Add your NVD API key to the .env file:
   ```
   NVD_API_KEY=your_api_key_here
   ```
   You can obtain an API key from: https://nvd.nist.gov/developers/request-an-api-key

## Docker Installation

### 1. Install Docker on Kali Linux
```bash
# Update package list
sudo apt update

# Install required packages
sudo apt install -y docker.io docker-compose

# Start and enable Docker service
sudo systemctl start docker
sudo systemctl enable docker

# Add your user to the docker group (optional, for running Docker without sudo)
sudo usermod -aG docker $USER
# Log out and log back in for the group changes to take effect
```

### 2. Clone the Repository
```bash
git clone https://github.com/yourusername/KMN-V-Scanner.git
cd KMN-V-Scanner
```

### 3. Configure Environment
```bash
# Copy example environment file
cp .env.example .env

# Edit the .env file with your NVD API key
nano .env
```

### 4. Build and Run with Docker Compose
```bash
# Build and start the container
docker-compose up -d

# View logs
docker-compose logs -f
```

The web interface will be available at: http://localhost:5000

### 5. Docker Commands Reference

#### Basic Operations
```bash
# Stop the container
docker-compose down

# Restart the container
docker-compose restart

# Rebuild and start (after making changes)
docker-compose up -d --build

# View container status
docker-compose ps
```

#### Data Management
```bash
# The data directory is mounted as a volume
# You can find your scan results in ./data/

# Backup the data directory
sudo cp -r data/ data_backup/

# Clean the data (if needed)
sudo rm -rf data/*
```

#### Troubleshooting Docker Installation

1. **Permission Issues**
   ```bash
   # If you can't access the data directory
   sudo chown -R $USER:$USER data/
   
   # If Docker commands fail
   sudo chmod 666 /var/run/docker.sock
   ```

2. **Network Issues**
   ```bash
   # Check if Docker container is running
   docker ps
   
   # Check container logs
   docker-compose logs
   
   # Restart Docker service
   sudo systemctl restart docker
   ```

3. **Container Issues**
   ```bash
   # Remove old containers and images
   docker-compose down
   docker system prune -a
   
   # Rebuild from scratch
   docker-compose up -d --build --force-recreate
   ```

### Docker Security Considerations

1. **Container Security**
   - The container runs as a non-root user
   - Only necessary ports are exposed (5000)
   - Volume mounts are read-write restricted
   - Container auto-restarts on failure

2. **Network Security**
   - Container uses Google DNS (8.8.8.8, 8.8.4.4)
   - Web interface only binds to localhost
   - Uses production Flask environment

3. **Data Persistence**
   - Scan data persists in the ./data volume
   - Database files are preserved between container restarts
   - Easy backup and restore through volume mounting

### Updating Docker Installation

1. **Update the Repository**
   ```bash
   git pull origin main
   ```

2. **Rebuild Container**
   ```bash
   docker-compose down
   docker-compose up -d --build
   ```

3. **Update Database**
   ```bash
   # Execute command inside container
   docker-compose exec vulnerability-scanner ./manage.sh download
   ```

## Verification Steps

1. **Verify Nmap Installation**
   ```bash
   nmap --version
   ```

2. **Verify Python Installation**
   ```bash
   python3 --version
   pip --version
   ```

3. **Test the Scanner**
   ```bash
   # Make the management script executable
   chmod +x manage.sh

   # Run a basic network discovery
   ./manage.sh discover 127.0.0.1

   # Run a basic port scan
   ./manage.sh scan localhost
   ```

## Additional Kali-Specific Setup

1. **Database Directory Setup**
   ```bash
   # Create data directory if it doesn't exist
   mkdir -p data
   chmod 755 data
   ```

2. **Optional: Create Desktop Shortcut**
   ```bash
   # Create a .desktop file
   cat > ~/.local/share/applications/kmn-scanner.desktop << EOL
   [Desktop Entry]
   Name=KMN V-Scanner
   Exec=bash -c "cd $(pwd) && ./manage.sh run"
   Type=Application
   Categories=Security;
   Comment=Vulnerability Scanner Tool
   Terminal=true
   Icon=utilities-terminal
   EOL
   ```

## Troubleshooting on Kali

1. **Permission Issues**
   ```bash
   # If you encounter permission issues with the data directory
   sudo chown -R $USER:$USER data/
   chmod 755 data/
   ```

2. **Python Package Issues**
   ```bash
   # If you encounter package conflicts
   pip install --upgrade pip
   pip install -r requirements.txt --force-reinstall
   ```

3. **Nmap Permission Issues**
   - For SYN scans and other privileged operations:
   ```bash
   sudo ./manage.sh scan target --scan-type SYN
   ```
   - For regular scans (no root required):
   ```bash
   ./manage.sh scan target
   ```

## Running the Web Interface

1. **Start the Web Application**
   ```bash
   ./manage.sh run
   ```

2. **Access the Interface**
   - Open your browser and navigate to: http://localhost:2025
   - The web interface works best with Firefox or Chromium (both pre-installed on Kali)

## Updating the Tool

1. **Update the Repository**
   ```bash
   git pull origin main
   ```

2. **Update Dependencies**
   ```bash
   source venv/bin/activate
   pip install -r requirements.txt --upgrade
   ```

3. **Update Vulnerability Database**
   ```bash
   ./manage.sh download
   ```

## Security Notes for Kali Users

1. **API Key Security**
   - Store your NVD API key securely in the `.env` file
   - Don't share your API key or commit it to version control
   - Consider using Kali's built-in encryption tools for additional security

2. **Network Scanning**
   - Be cautious when scanning networks
   - Ensure you have permission to scan target networks
   - Use Kali's built-in VPN or proxy tools when necessary

3. **Database Security**
   - The tool stores data in SQLite databases in the `data/` directory
   - Consider encrypting sensitive scan results
   - Regularly backup your database files

## Integration with Other Kali Tools

KMN V-Scanner can be used alongside other Kali Linux security tools:

1. **Metasploit Integration**
   - Use scan results to identify potential targets
   - Export scan results for use in Metasploit

2. **Report Generation**
   - Use Kali's document tools to process scan reports
   - Integrate with custom reporting scripts

## Getting Help

If you encounter any issues specific to running KMN V-Scanner on Kali Linux:

1. Check the troubleshooting section above
2. Review the main README.md file
3. Submit an issue on the GitHub repository
4. Check the Kali Linux forums for similar issues
