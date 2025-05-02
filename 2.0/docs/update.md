# Using the Fixed proc-wolf Version

I've completely rewritten the core threat evaluation and response system in proc-wolf to make it much less aggressive while still protecting you from actual threats. Here's how to use the new version:

## What's Been Fixed

1. **Expanded Trusted Applications List**: Now includes browsers, development tools, system utilities, and all common legitimate applications

2. **Interactive Application Protection**: Applications with visible windows are now considered much less suspicious

3. **Active Application Immunity**: Applications you're actively using will never be touched

4. **Conservative Action Levels**: Higher thresholds before taking action against processes

5. **Confirmation Required**: A popup confirmation is now required before nuking any process

6. **New Whitelist System**: Easy way to add trusted applications

## How to Use the Whitelist

The system now includes a `whitelist.txt` file that will be created in the same directory as proc-wolf. You can add:

1. **Application names**: Just add the executable name (e.g., `vivaldi.exe`)
2. **Paths**: Add full paths to trusted folders (anything in those folders will be trusted)

Whitelist entries are automatically trusted and will never be flagged or touched.

## Installation Steps

1. Replace your `proc_wolf.py` file with the fixed version I provided
2. Rebuild the executables using your build script
3. Use the executables as before

## Running the Fixed Version

All three modes (CLI, system tray, and service) work exactly the same as before, but with much more conservative behavior.

### System Tray Mode

```
ProcWolf.exe
```
Look for the wolf icon in your system tray.

### Command Line Mode

```
ProcWolfCLI.exe [command] [options]
```
All the commands work the same.

### Service Mode

```
ProcWolfService.exe --startup auto install
net start ProcWolfService
```
Or use the install.bat script.

## Customizing Sensitivity

If you want to further adjust the sensitivity of proc-wolf, you can modify these sections of the code:

1. **Threat Score Thresholds**: The `evaluate_threat_level` function now has higher thresholds for threat levels
2. **Action Level Thresholds**: The `get_action_level` function now requires more warnings before taking action

## Watching the Logs

The logs will now show you when processes are being monitored but action is not being taken because:
- The process has a GUI window
- You're actively using the application
- The application is in your whitelist

This will help you understand why certain suspicious-looking processes are being left alone.

## What to Do If Too Many/Few Detections

If you're still getting too many detections:
1. Add more applications to your whitelist.txt
2. Increase the thresholds in the code further

If you're getting too few detections:
1. Reduce the thresholds in evaluate_threat_level function
2. Reduce the warning requirements in get_action_level function

## Expected Behavior

With these changes, you should see:
1. Normal applications like browsers, terminals, and development tools never flagged
2. Applications you're actively using never interrupted
3. Confirmation prompts before any drastic actions
4. Actual malware still detected and handled

The wolf is still vigilant, but now it knows the difference between your tools and actual threats!