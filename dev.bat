@echo off
echo Starting KeyCloak Assistant development environment...

start "Tailwind CSS Watch" cmd /k "build-css.bat"
timeout /t 2 /nobreak > nul

echo Starting application...
dotnet run
