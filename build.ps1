# build.ps1

# Ensure Python and PyInstaller are installed
Write-Host "Checking dependencies..."
if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Host "Error: Python is not installed or not in PATH." -ForegroundColor Red
    exit 1
}
if (-not (Get-Command pyinstaller -ErrorAction SilentlyContinue)) {
    Write-Host "Installing PyInstaller..."
    python -m pip install pyinstaller
}

# Install required Python packages
Write-Host "Installing Python dependencies..."
python -m pip install tweepy>=4.16.0 PyQt6 requests python-dateutil cryptography

# Clean previous build artifacts
Write-Host "Cleaning previous build artifacts..."
Remove-Item -Recurse -Force -ErrorAction SilentlyContinue dist, build, *.spec

# Run PyInstaller to create a single .exe
Write-Host "Building executable..."
pyinstaller --onefile `
    --name poster `
    --add-data "client.log;." `
    --log-level WARN `
    poster.py

# Check if build was successful
if ($LASTEXITCODE -eq 0) {
    Write-Host "Build successful! Executable is located at: dist\poster.exe" -ForegroundColor Green
    
    # Copy the .exe to the current directory
    Write-Host "Copying executable to current directory..."
    Copy-Item -Path "dist\poster.exe" -Destination "."
    
    # Clean up build artifacts
    Write-Host "Cleaning up build artifacts..."
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue dist, build, *.spec
    
    Write-Host "Build complete. Run poster.exe to start the application."
    Write-Host "Credentials will be stored in social_credentials.enc in the same directory."
    Write-Host "Fernet key will be stored in fernet_key.key. Keep this file secure and do not delete it!"
} else {
    Write-Host "Build failed. Check PyInstaller logs for details." -ForegroundColor Red
    exit 1
}