# Run this script to fix your PyWin32 installation

# First, uninstall any existing pywin32 package
pip uninstall -y pywin32

# Then reinstall the specific version
pip install pywin32==306

# Run the post-install script to ensure proper setup
python -m pywin32_postinstall -install

# If the above doesn't work, you might need to locate and run the post-install script manually
# Uncomment and adjust the path as needed:
# python C:\Path\To\Your\Python\Scripts\pywin32_postinstall.py -install

# Verify the installation
pip list | grep pywin32

echo "Installation complete! Try running your script again."