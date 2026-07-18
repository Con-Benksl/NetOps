@echo off
set "ROOT=%~dp0.."
python "%ROOT%\scripts\netopsctl.py" %*
