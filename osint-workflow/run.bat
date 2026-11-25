@echo off
rem Point d'entree Windows : run.bat --mandat REF --email x@y.fr --username pseudo
if not exist "%~dp0venv\Scripts\python.exe" (
    echo [!] venv introuvable. Creation automatique...
    py -m venv "%~dp0venv"
    "%~dp0venv\Scripts\pip.exe" install -r "%~dp0requirements-cli.txt" 2>nul
)
"%~dp0venv\Scripts\python.exe" "%~dp0scripts\osint_runner.py" %*
