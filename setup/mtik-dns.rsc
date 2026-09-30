/ip/dns/set cache-size=20000
/ip/dns/adlist/add url=https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/gambling-porn/hosts
/ip/dns/adlist/add url=https://blacklists.pages.dev/dist/hosts/threat.txt disabled=yes
/ip/dns/static
add cname=strict.bing.com name=www.bing.com type=CNAME comment="safe.bl.dennyhalim.com"
add address=216.239.38.119 regexp=www.google.co type=A comment="safe.bl.dennyhalim.com"
add regexp="(casino|poker|bingo|slots|gambling)" type=NXDOMAIN comment="nsfw.bl.dennyhalim.com"
add regexp="(adult|lgbt|xxx|porn|sexy|webcam)" type=NXDOMAIN comment="nsfw.bl.dennyhalim.com"
add regexp="(doubleclick|booru|2mdn|pagead2|quantserve)" type=NXDOMAIN comment="ads.bl.dennyhalim.com"
add regexp="(analyti|telemetry|beacon|tracking|nexusrules|piwik)" type=NXDOMAIN comment="trackers.bl.dennyhalim.com"
add regexp=".*\\.(bet|bid|cfd|icu|tk|top)\$" type=NXDOMAIN comment="tld.bl.dennyhalim.com"
add regexp=".*\\.(cam|gay|gq|sex|tube)\$" type=NXDOMAIN comment="tld.bl.dennyhalim.com"
add regexp="google(ad|tag|syndication|-analytic)" type=NXDOMAIN comment="google.bl.dennyhalim.com"
add regexp="ad(serv|vert|mob|zerk|nxs|system|tube)" type=NXDOMAIN comment="ads.bl.dennyhalim.com"
add regexp="(bing|mail-|search|image|video|samsung|tv)ads" type=NXDOMAIN comment="ads.bl.dennyhalim.com"
add regexp="(steam|flix|nflx|scdn|spotifycdn|spotify-com|spotify.map)" type=NXDOMAIN comment="bw.bl.dennyhalim.com" disabled=yes
add regexp="(tiktokv|tiktokw|tiktokcdn|ttwstatic|ttdns|bytedns)" type=NXDOMAIN comment="bw.bl.dennyhalim.com" disabled=yes
