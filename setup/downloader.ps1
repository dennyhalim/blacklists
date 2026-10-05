$ppath="$env:programdata\Polaris\temp"
mkdir "$ppath"
del /s /f "$ppath"
compact.exe /s /c "$ppath"
cd "$ppath"
curl.exe -o dhbl.zip https://codeload.github.com/dennyhalim/blacklists/zip/refs/heads/main
Expand-Archive "dhbl.zip" -Force
move .\dhbl\blacklists-main\dist\ ..
