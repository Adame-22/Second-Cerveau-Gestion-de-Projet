@echo off
rem Point d'entree Windows : run.bat --mandat REF --email x@y.fr --username pseudo
"%~dp0venv\Scripts\python.exe" "%~dp0scripts\osint_runner.py" %*
