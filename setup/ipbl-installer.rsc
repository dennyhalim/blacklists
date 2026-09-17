# MikroTik blacklist installer
# RouterOS v7
# bl.dennyhalim.com

# note: you must adjust firewall src-address-list accordingly
:local blacklistUrl "https://blacklists.pages.dev/dist/mikrotik/combined.rsc"
:local interval "13h"

:local downloaderName "dhbl-downloader"
:local schedulerName "dhbl-updater"
:local downloadFile "dhblacklist.rsc"

# Add firewall rules. adjust src-address-list according to url filename
# ganti nama src-adddress-list sesuai nama ip list yang digunakan dari bl.dennyhalim.com
/ip/firewall/raw/add chain=prerouting action=drop log-prefix=dhbl comment=bl.dennyhalim.com place-before=0 src-address-list=dhblocklist-combined

# Remove previous installation
/system scheduler remove [find where name=$schedulerName]
/system script remove [find where name=$downloaderName]

# Create downloader
/system script add \
    name=$downloaderName \
    policy=ftp,read,write,policy,test \
    source=("
:local url \"" . $blacklistUrl . "\"
:local file \"" . $downloadFile . "\"

:log info \"bl.dennyhalim.com : downloading update\"

:do {
    /file remove [find where name=\$file]
} on-error={}

:do {
    /tool fetch url=\$url dst-path=\$file 
} on-error={
    :log error \"bl.dennyhalim.com : download failed\"
    :error \"bl.dennyhalim.com download failed\"
}

:if ([:len [/file find where name=\$file]] = 0) do={
    :log error \"bl.dennyhalim.com : downloaded file not found\"
    :error \"bl.dennyhalim.com file missing\"
}

:log info \"bl.dennyhalim.com : executing downloaded script\"

:do {
    /import file-name=\$file
} on-error={
    :log error \"bl.dennyhalim.com : import failed\"
    :error \"bl.dennyhalim.com import failed\"
}

:log info \"bl.dennyhalim.com : update completed\"
")

# Create scheduler
/system scheduler add \
    name=$schedulerName \
    interval=$interval \
    start-time=startup \
    on-event=$downloaderName \
    policy=ftp,read,write,policy,test

:log info "bl.dennyhalim.com : installer completed"
:log info ("bl.dennyhalim.com : update interval = " . $interval)
