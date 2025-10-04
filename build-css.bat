@echo off
echo Watching CSS changes...

:watch
./tailwindcss.exe --input wwwroot/css/input.css --output wwwroot/css/tailwind.css --minify --watch
echo CSS compiled. Watching for changes...
goto watch
