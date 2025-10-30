# Contributing to Proc-Wolf

Thank you for your interest in improving Proc-Wolf! We welcome contributions that help make Windows systems safer.

## 🎯 Quick Start

1. **Fork** the repository
2. **Clone** your fork: `git clone https://github.com/whisprer/proc-wolf.git`
3. **Create** a feature branch: `git checkout -b feature/amazing-feature`
4. **Commit** your changes: `git commit -m 'feat: add amazing feature'`
5. **Push** to your fork: `git push origin feature/amazing-feature`
6. **Open** a Pull Request

## 📋 Development Setup

### Prerequisites
- Windows 10/11 (64-bit)
- Python 3.8+
- Administrator privileges (for testing)
- Visual Studio Code or similar IDE

### Environment Setup
```bash
# Clone the repo
git clone https://github.com/yourusername/proc-wolf.git
cd proc-wolf

# Create virtual environment
python -m venv venv
venv\Scripts\activate  # On Windows

# Install dependencies
pip install -r requirements.txt

# Run tests in debug mode
python proc_wolf.py
```

## 🔧 Code Style

### Python Standards
- Follow **PEP 8** conventions
- Use type hints where appropriate
- Maximum line length: 120 characters
- Use descriptive variable names

### Before Committing
```bash
# Format code
black proc_wolf.py

# Check for issues
pylint proc_wolf.py
mypy proc_wolf.py

# Run tests
python -m pytest tests/
```

### Commit Messages
Follow conventional commits:
- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation changes
- `style:` Code style changes
- `refactor:` Code refactoring
- `test:` Test additions/changes
- `chore:` Maintenance tasks

Examples:
```
feat: add process memory analysis
fix: correct Windows 11 process detection
docs: update whitelist documentation
```

## 🏗️ Project Structure

```
proc-wolf/
├── proc_wolf.py           # Core engine
├── windows_processes.py   # Process whitelist
├── proc_wolf_service.py   # Service wrapper
├── build_exe.py          # Build script
├── tests/                # Unit tests
│   ├── test_detection.py
│   ├── test_whitelist.py
│   └── test_actions.py
└── docs/                 # Documentation
    ├── WHITELIST.md
    └── DETECTION.md
```

## 🧪 Testing

### Running Tests
```bash
# All tests
python -m pytest

# Specific module
python -m pytest tests/test_detection.py

# With coverage
python -m pytest --cov=proc_wolf
```

### Test Guidelines
- Test both positive and negative cases
- Mock Windows API calls appropriately
- Test with various Windows versions
- Include edge cases (System Idle Process, etc.)

### Manual Testing Checklist
- [ ] Service installs correctly
- [ ] Service starts without timeout
- [ ] Service stops gracefully
- [ ] No false positives on clean system
- [ ] Detects test malware samples
- [ ] Database operations work correctly
- [ ] Logs are being written

## 🛡️ Security Considerations

### When Adding Detection Logic
1. **Be Conservative**: False positives are worse than false negatives
2. **Test Thoroughly**: Especially with system processes
3. **Document Patterns**: Explain why something is suspicious
4. **Consider Performance**: Don't slow down the system

### Whitelist Additions
When adding to `windows_processes.py`:
- Verify it's a legitimate Microsoft/trusted process
- Include version information if relevant
- Document why it needs whitelisting
- Test on multiple Windows versions

## 📝 Documentation

### Code Documentation
- All functions need docstrings
- Complex logic needs inline comments
- Update README.md for user-facing changes
- Update CHANGELOG.md for all changes

### Example Docstring
```python
def evaluate_threat_level(process_info: Dict) -> int:
    """
    Evaluate the threat level of a process.
    
    Args:
        process_info: Dictionary containing process details
        
    Returns:
        Threat level from 0 (TRUSTED) to 4 (CRITICAL)
        
    Note:
        Conservative evaluation to minimize false positives
    """
```

## 🐛 Reporting Issues

### Bug Reports Should Include
- Windows version (10/11, build number)
- Proc-Wolf version
- Steps to reproduce
- Expected behavior
- Actual behavior
- Relevant log excerpts
- Process name/path if applicable

### Feature Requests Should Include
- Use case description
- Expected behavior
- Why it would benefit users
- Potential implementation approach

## 💡 Areas We Need Help

- **Process Detection**: New malware patterns
- **Performance**: Optimization for large process counts
- **Documentation**: Tutorials and guides
- **Testing**: Edge cases and compatibility
- **UI/UX**: System tray improvements
- **Localization**: Multi-language support

## ⚠️ What NOT to Submit

- Malware samples (link to VirusTotal instead)
- Exploits or attack tools
- Code that bypasses Windows security
- Unethical use cases
- Large binary files

## 📊 Pull Request Process

1. **Update** documentation
2. **Add** tests for new features
3. **Ensure** all tests pass
4. **Update** CHANGELOG.md
5. **Request** review from maintainers
6. **Address** review feedback
7. **Squash** commits if requested

## 🏆 Recognition

Contributors will be:
- Listed in CONTRIBUTORS.md
- Mentioned in release notes
- Given credit in commit messages

## 📞 Communication

- **Issues**: Bug reports and feature requests
- **Discussions**: General questions and ideas
- **Pull Requests**: Code contributions
- **Security**: Private disclosure (see SECURITY.md)

---

Thank you for helping make Proc-Wolf better! Every contribution helps protect Windows users.

🐺 *"Together we guard the gate"*
