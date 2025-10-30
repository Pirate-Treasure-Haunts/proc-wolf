# Security Policy

## 🛡️ Proc-Wolf Security

Proc-Wolf is a defensive security tool designed to protect Windows systems from malicious processes. We take security seriously and appreciate responsible disclosure of vulnerabilities.

## ✅ Supported Versions

| Version | Support Status   | Security Updates |
|---------|------------------|------------------|
| 3.1.x   | ✅ Active        | Immediate        |
| 3.0.x   | ⚠️ Critical only | As needed        |
| < 3.0   | ❌ Unsupported   | None             |

**Note:** Version 4.0.0 has known issues with false positives. Users should upgrade to 4.1.x immediately.

## 🔍 Reporting a Vulnerability

### For Security Vulnerabilities

If you discover a security vulnerability in Proc-Wolf:

1. **DO NOT** open a public GitHub issue
2. **DO NOT** exploit the vulnerability
3. **DO** report it privately via one of these channels:
   - GitHub Security Advisory: [Report a vulnerability](https://github.com/whisprer/proc-wolf/security/advisories/new)
   - Email: security@whispr.dev
   - GPG Key: [Available on Keybase](https://keybase.io/yourusername)

### What to Include

Please provide:
- Affected version(s)
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested mitigation (if any)

### Response Timeline

- **Initial Response:** Within 72 hours
- **Status Update:** Within 7 days
- **Fix Timeline:** Depends on severity
  - Critical: 24-48 hours
  - High: 3-5 days
  - Medium: 1-2 weeks
  - Low: Next release

## ⚠️ Security Scope

### In Scope
- Bypass of threat detection
- Privilege escalation through Proc-Wolf
- Denial of service attacks
- Information disclosure
- Process whitelist bypass
- Database manipulation
- Service vulnerabilities

### Out of Scope
- Windows OS vulnerabilities
- Third-party library issues (report upstream)
- Social engineering
- Physical access attacks
- Already documented limitations

## 🚨 Known Security Considerations

### Privilege Requirements
Proc-Wolf requires Administrator privileges to:
- Monitor system processes
- Terminate malicious processes
- Access Windows APIs
- Install as a service

**Risk Mitigation:** The service runs under Local System account with minimal required privileges.

### Database Security
- Location: `C:\ProgramData\proc-wolf\proc-wolf.db`
- Contains: Process history, whitelist, threat patterns
- **Risk:** Information disclosure if accessed
- **Mitigation:** Restricted NTFS permissions

### Quarantine Directory
- Location: `C:\ProgramData\proc-wolf\quarantine\`
- Contains: Isolated malicious executables
- **Risk:** Malware escape if permissions compromised
- **Mitigation:** Restricted access, renamed extensions

### Detection Limitations
Proc-Wolf uses heuristic detection and may not catch:
- Zero-day exploits
- Fileless malware
- Advanced persistent threats (APTs)
- Nation-state level attacks

## 🔐 Security Best Practices

### For Users
1. Keep Proc-Wolf updated (auto-update coming in v4.0)
2. Regularly review quarantine folder
3. Monitor service logs for anomalies
4. Don't disable without good reason
5. Report suspicious behavior

### For Developers
1. Never weaken whitelist without review
2. Test thoroughly on clean Windows installs
3. Validate all user inputs
4. Use secure coding practices
5. Review dependencies regularly

## 🏗️ Security Features

### Current (v4.1.x)
- ✅ Process whitelisting (216+ Windows processes)
- ✅ Digital signature verification
- ✅ Behavioral analysis
- ✅ Quarantine isolation
- ✅ Service hardening
- ✅ Conservative action thresholds

### Planned (v5.0)
- [ ] Encrypted database
- [ ] Secure update mechanism
- [ ] Code signing certificate
- [ ] Audit logging
- [ ] SIEM integration
- [ ] Machine learning models

## 📊 Vulnerability Disclosure Policy

We follow responsible disclosure:

1. **Reporter** privately discloses vulnerability
2. **We** acknowledge within 72 hours
3. **We** develop and test fix
4. **We** release patched version
5. **We** publish security advisory
6. **Reporter** may publish details (after 90 days or patch)

### Hall of Fame

We recognize security researchers who help improve Proc-Wolf:
- *Your name here* - Be the first!

## 🆘 Emergency Contacts

For critical vulnerabilities being actively exploited:
- Emergency: [emergency contact]
- Backup: [backup contact]

## 🔄 Version History

### Security Updates
- **v4.1.1** - Fixed service privilege issues
- **v4.1.0** - Fixed false positive crisis (was attacking Windows)
- **v4.0.0** - Initial release (⚠️ too aggressive)

## 📝 Security Audit

Last external audit: *Not yet performed*
Next planned audit: *When reaching v4.0*

## ⚖️ Legal

### Responsible Testing
When testing Proc-Wolf:
- Only test on systems you own
- Don't test against production systems
- Use isolated VMs when possible
- Never distribute malware samples

### No Warranty
Proc-Wolf is provided "as-is" without warranty. It's a defensive tool and not a guarantee against all threats.

---

**Remember:** Security is a shared responsibility. Proc-Wolf is one layer of defense, not a complete solution.

🐺 *"Vigilance is the price of security"*

---

This security policy is based on industry best practices and may be updated as the project evolves.

Last updated: October 2025
