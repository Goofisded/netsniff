<!-- BANNER IMAGE -->
<!-- Replace URL with your actual banner image -->
<div align="center">
  <img src="https://cdn.discordapp.com/attachments/1344733909598077129/1349036945199861810/image.png?ex=67d1a40f&is=67d0528f&hm=a8602cf6cf5bfcfad42a038d5aeebcb6d50f2d11e3e8a48ac0035ff44b724d6b&" alt="NetSniff Banner">
  
  <br>
  
  [![Python Version](https://img.shields.io/badge/Python-3.8%2B-blue)](https://python.org)
  [![License: MIT](https://img.shields.io/badge/License-MIT-yellowgreen)](LICENSE)
  [![Open Source](https://badges.frapsoft.com/os/v1/open-source.svg?v=103)](https://opensource.org)

  <h1>NetSniff 🔍</h1>
  <h3>Advanced Network Monitoring & Security Analysis Tool</h3>
</div>

## Table of Contents
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage) 
- [Configuration](#configuration)
- [Screenshots](#screenshots)
- [Contributing](#contributing)
- [License](#license)

## Features ✨
- Real-time network traffic monitoring
- Port scan detection & threat alerts
- DNS query logging & analysis
- Protocol breakdown (TCP/UDP/ICMP)
- Connection tracking & statistics
- Cross-platform support (Windows/Linux/macOS)
- Customizable whitelists & thresholds

## Installation 💻

### Prerequisites
- Python 3.8+
- Npcap (Windows) / libpcap (Linux)

```bash
# Clone repository
git clone https://github.com/Goofisded/netsniff.git
cd netsniff

# Install dependencies
pip install -r requirements.txt
```

### Linux Setup
```bash
# Install libpcap
sudo apt-get install libpcap-dev

# Run with privileges
sudo python3 netsniff.py -i eth0
```

### Windows Setup

-Install [Npcap](https://npcap.com)
-Run Command Prompt as Admin:

```cmd
python netsniff.py -i "Ethernet"
```

## Usage 🚀

Basic command structure:
```bash
sudo python3 netsniff.py -i [interface]
```
Example with common interface names:
```bash
# Linux wireless interface
sudo python3 netsniff.py -i wlp2s0

# Windows Ethernet
python netsniff.py -i "Ethernet 2"
```

## Configuration ⚙️

Edit the `CONFIG` section in the code:
```python
CONFIG = {
    "CHECK_INTERVAL": 5,      # Stats refresh rate (seconds)
    "SCAN_THRESHOLD": 15,     # SYN packets/min for alerts
    "DNS_THRESHOLD": 50,      # DNS queries/min limit
    "WHITELISTED_IPS": [],    # Trusted IP addresses
    "LOG_FILE": "netsniff.log"# Log file path
}
```

## Screenshots 📸

<!-- Replace with actual screenshot URLs -->
<div align="center">
<img src="https://cdn.discordapp.com/attachments/1344733909598077129/1349039462968983562/image.png?ex=67d1a667&is=67d054e7&hm=591d92578f955bcf1ca8cc1c39aef907125c64cbb90e44a9194f9d2538dd97b5&" width="45%"> 
<img src="https://cdn.discordapp.com/attachments/1344733909598077129/1349039810416742570/image.png?ex=67d1a6ba&is=67d0553a&hm=0f22b89588713ab1f820e2cba3f579263138faf1cbdb5e713c2282699c424750&" width="45%"> </div>

## Contributing 🤝

-Fork the repository
-Create your feature branch:
```bash
git checkout -b feature/amazing-feature
```
-Commit changes:
```bash
git commit -m 'Add amazing feature'
```
-Push to branch:
```bash
git push origin feature/amazing-feature
```
-Open a Pull Request

## License 📄

Distributed under MIT License. See LICENSE for more information.

<div align="center"> Made with ❤️ by Goofisded | 🛡️ Happy Monitoring! </div>








