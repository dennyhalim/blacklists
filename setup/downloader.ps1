cd $env:temp
$ppath="$env:programdata\Polaris\temp"
mkdir "$ppath"
Remove-Item "$ppath\blacklists-main" -Recurse
compact.exe /s /c "$ppath"  
curl.exe -o dhbl.zip https://codeload.github.com/dennyhalim/blacklists/zip/refs/heads/main
Expand-Archive "dhbl.zip"  -DestinationPath "$ppath" -Force
move "$ppath\blacklists-main\dist\" "$ppath\.."
Remove-Item .\dhbl.zip
