[README.md]

# 🐺 Proc-Wolf - Advanced Windows Process Monitor

<p align="center">
  <a href="https://github.com/whisprer/proc-wolf/releases">
    <img src="https://img.shields.io/github/v/release/whisprer/proc-wolf?color=4CAF50&label=release" alt="Release Version">
  </a>
  <a href="https://github.com/whisprer/proc-wolf/actions">
    <img src="https://img.shields.io/github/actions/workflow/status/whisprer/proc-wolf/lint-and-plot.yml?label=build" alt="Build Status">
  </a>
</p>

![Commits](https://img.shields.io/github/commit-activity/m/whisprer/proc-wolf?label=commits)
![Last Commit](https://img.shields.io/github/last-commit/whisprer/proc-wolf)
![Issues](https://img.shields.io/github/issues/whisprer/proc-wolf)
[![Version](https://img.shields.io/badge/version-3.1.1-blue.svg)](https://github.com/yourusername/proc-wolf)
[![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11-lightgrey.svg)](https://www.microsoft.com/windows)
[![Python](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

<p align="center">
  <img src="proc-wolf-banner.png" width="850" alt="Proc-Wolf Banner">
</p>

A sophisticated Windows process monitoring and threat detection system that guards your system against malicious processes while respecting legitimate software.

## Features

### Core Capabilities
- **Real-time Process Monitoring**: Continuously monitors all running processes
- **Multi-layered Threat Detection**: Uses behavioral analysis, signature verification, and heuristic patterns
- **Conservative Action System**: Graduated response system (Monitor → Warn → Kill → Quarantine → Nuke)
- **Comprehensive Windows Recognition**: Whitelists 216+ legitimate Windows processes and services
- **Self-Protection**: Won't attack itself or critical system components
- **Automatic Quarantine**: Isolates suspicious executables safely

### Deployment Options
- **Windows Service**: Runs silently in the background with automatic startup
- **System Tray Application**: User-friendly interface with notifications
- **Command Line Interface**: Direct control for power users
- **Debug Mode**: For testing and troubleshooting

## Quick Start

### Prerequisites
- Windows 10/11 (64-bit)
- Administrator privileges
- Python 3.8+ (for building from source)

### Installation

#### Option 1: Pre-built Release (Recommended)
1. Download the latest release from [Releases](https://github.com/yourusername/proc-wolf/releases)
2. Extract to your preferred location
3. Right-click `install.bat` and select "Run as administrator"
4. The service will start automatically

#### Option 2: Build from Source
```bash
# Clone the repository
git clone https://github.com/yourusername/proc-wolf.git
cd proc-wolf

# Install dependencies
pip install -r requirements.txt

# Build executables
python build_exe.py

# Install the service
cd dist
install.bat
```

## Usage

### Service Control
Use `service_control.bat` for easy management:
```
1. STATUS  - Check service status
2. START   - Start the service
3. STOP    - Stop the service gracefully
4. RESTART - Restart the service
5. KILL    - Force kill all instances
6. CLEAN   - Complete removal
7. DEBUG   - Run in debug mode
```

### Command Line Interface
```bash
# List all processes with threat assessment
ProcWolfCLI.exe list --assess

# Assess a specific process
ProcWolfCLI.exe assess --name suspicious.exe

# Kill a dangerous process
ProcWolfCLI.exe kill --name malware.exe

# Complete removal of a process
ProcWolfCLI.exe nuke --name virus.exe

# View process history
ProcWolfCLI.exe history

# Real-time monitoring
ProcWolfCLI.exe monitor
```

### System Tray Monitor
Run `ProcWolf.exe` for a user-friendly system tray interface with:
- Real-time notifications
- Quick access to controls
- Visual status indicators

## Security Model

### Threat Levels
- **TRUSTED (0)**: Known legitimate processes
- **LOW (1)**: Minor suspicion indicators
- **MEDIUM (2)**: Multiple suspicious characteristics
- **HIGH (3)**: Strong malware indicators
- **CRITICAL (4)**: Confirmed malicious behavior

### Action Thresholds
- **MONITOR**: Observe only (LOW threat)
- **WARN**: Alert user (MEDIUM threat, 10+ warnings)
- **KILL**: Terminate process (MEDIUM threat, 20+ warnings)
- **QUARANTINE**: Isolate executable (HIGH threat, 15+ warnings)
- **NUKE**: Complete removal with resurrection prevention (CRITICAL threat, confirmed)

## Configuration

### Database Location
`C:\ProgramData\proc-wolf\proc-wolf.db`

### Log Files
- Service logs: `C:\ProgramData\proc-wolf\proc-wolf-service.log`
- Background logs: `%LOCALAPPDATA%\proc-wolf\proc-wolf-background.log`
- CLI logs: `proc-wolf-cli.log` (executable directory)

### Quarantine Directory
`C:\ProgramData\proc-wolf\quarantine\`

## 🏗️ Architecture

```
proc-wolf/
├── proc_wolf.py            # Core monitoring engine
├── proc_wolf_service.py    # Windows service wrapper
├── proc_wolf_background.py # System tray application
├── proc_wolf_full_4-0.py   # CLI interface
├── windows_processes.py    # Windows process whitelist
├── build_exe.py            # Build automation script
├── service_control.bat
| dist/                     # Compiled executables
|   ├── ProcWolf.exe
|   ├── ProcWolfCLI.exe
|   ├── ProcWolfService.exe
|   ├── install.bat
|   ├── uninstall.bat
|   └── service_control.bat
├── README.md
├── LICENCE.md
├── CHANGELOG.md
├── CODE_OF_CONDUCT.md
├── CONTRIBTING.md
└── SECURITY.md
```

## Version History

### v4.1.1 (Current)
- Fixed service startup/shutdown timing
- Added graceful shutdown support
- Auto-generated service control utilities
- Improved build process

### v4.1.0
- Comprehensive Windows process recognition (216+ processes)
- Fixed database schema issues
- Conservative action thresholds
- Self-protection mechanisms

### v4.0.0
- Initial public release
- Multi-layered threat detection
- Graduated response system

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## Disclaimer

This software is provided as-is for educational and security research purposes. While extensively tested, use at your own risk. Always maintain backups and test in a controlled environment first.

## License

This project is licensed under a Hybrid MIT/CC0 License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Built with Python, psutil, and pywin32
- Threat detection patterns inspired by industry best practices
- Windows process identification based on official Microsoft documentation
- Thnx to Claude Opus4.1 for all his fine halps

## Support

- **Issues**: [GitHub Issues](https://github.com/yourusername/proc-wolf/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/proc-wolf/discussions)
- **Security**: For security vulnerabilities, please email directly

---

**Note**: Proc-Wolf is designed to be a defensive tool. It employs conservative thresholds and multiple confirmation steps before taking action against any process. The goal is protection without disruption of legitimate software.

🐺 *"A disciplined guardian, not a rabid beast"*

Made with love for all you system defenders out there. 🐺 Stay safe.

---
