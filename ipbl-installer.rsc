# MikroTik blacklist installer
# RouterOS v7
# ipbl.dennyhalim.com

:local blacklistUrl "https://blacklists.pages.dev/dist/mikrotik/combined1.rsc"
:local interval "8h"

:local downloaderName "ipbl-downloader"
:local schedulerName "ipbl-updater"
:local downloadFile "ipblacklist.rsc"

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

:log info \"ipbl.dennyhalim.com : downloading update\"

:do {
    /file remove [find where name=\$file]
} on-error={}

:do {
    /tool fetch url=\$url dst-path=\$file 
} on-error={
    :log error \"ipbl.dennyhalim.com : download failed\"
    :error \"ipbl.dennyhalim.com download failed\"
}

:if ([:len [/file find where name=\$file]] = 0) do={
    :log error \"ipbl.dennyhalim.com : downloaded file not found\"
    :error \"ipbl.dennyhalim.com file missing\"
}

:log info \"ipbl.dennyhalim.com : executing downloaded script\"

:do {
    /import file-name=\$file
} on-error={
    :log error \"ipbl.dennyhalim.com : import failed\"
    :error \"ipbl.dennyhalim.com import failed\"
}

:log info \"ipbl.dennyhalim.com : update completed\"
")

# Create scheduler
/system scheduler add \
    name=$schedulerName \
    interval=$interval \
    start-time=startup \
    on-event=$downloaderName \
    policy=ftp,read,write,policy,test

:log info "ipbl.dennyhalim.com : installer completed"
:log info ("ipbl.dennyhalim.com : update interval = " . $interval)
