cd $env:temp
$ppath="$env:programdata\Polaris"
mkdir "$ppath\temp"
Remove-Item "$ppath\dist" -Recurse
Remove-Item "$ppath\temp\blacklists-main" -Recurse
compact.exe /s /c "$ppath\temp"  
curl.exe -o dhbl.zip https://codeload.github.com/dennyhalim/blacklists/zip/refs/heads/main
Expand-Archive "dhbl.zip"  -DestinationPath "$ppath\temp" -Force
move "$ppath\temp\blacklists-main\dist\" "$ppath"
Remove-Item .\dhbl.zip
