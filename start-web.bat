@echo off
cd /d "%~dp0\web"
echo Starting Packet Sniffer Web Interface...
echo Access at: http://localhost:5000
echo WARNING: Requires administrator privileges for packet capture
py app.py
pause