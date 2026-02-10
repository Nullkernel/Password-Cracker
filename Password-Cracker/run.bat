@echo off
:: Run as admin with the canonical CLI entry point
powershell -Command "Start-Process 'python.exe' -ArgumentList '-m cracker.cli' -Verb runAs"
