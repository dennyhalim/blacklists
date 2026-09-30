/ip/dns/set cache-size=20000
/ip/dns/adlist/add url=https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/gambling-porn/hosts
/ip/dns/adlist/add url=https://blacklists.pages.dev/dist/hosts/threat.txt disabled=yes
/ip/dns/static
add cname=strict.bing.com name=www.bing.com type=CNAME comment="safe.bl.dennyhalim.com"
add address=216.239.38.119 regexp=www.google.co type=A comment="safe.bl.dennyhalim.com"
add regexp="(casino|poker|bingo|slots|gambl)" type=NXDOMAIN comment="nsfw.bl.dennyhalim.com"
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
add regexp="(cerberhhyed5frqa|lfdachijzuwx4bc4|hjhqmbxyinislkkt)" type=NXDOMAIN comment="malw.bl.dennyhalim.com"
add regexp="(27lelchgcvs2wpm7|32kl2rwsjvqjeui7|3qbyaoohkcqkzrz6)" type=NXDOMAIN comment="malw.bl.dennyhalim.com"
add regexp="(52uo5k3t73ypjije|ahuqfrqk54v3vnzj|avsxrcoq2q5fgrw2)" type=NXDOMAIN comment="malw.bl.dennyhalim.com"
add regexp="(ffoqr3ug7m726zou|fnmi62725zfti2vy|ftoxmpdipwobp4qy)" type=NXDOMAIN comment="malw.bl.dennyhalim.com"
add regexp="(mz7oyb3v32vshcvk|ojmekzw4mujvqeju|oqwygprskqv65j72)" type=NXDOMAIN comment="malw.bl.dennyhalim.com"
add regexp="(pmenboeqhyrpvomq|qfjhpgbefuhenjp7|stgg5jv6mqiibmax)" type=NXDOMAIN comment="malw.bl.dennyhalim.com"
add regexp="(vrvis6ndra5jeggj|vrympoqs5ra34nfo|vyohacxzoue32vvk)" type=NXDOMAIN comment="malw.bl.dennyhalim.com"
add regexp="(4w5wihkwyhsav2ha|4kqd3hmqgptupi3p|de2nuvwegoo32oqv)" type=NXDOMAIN comment="malw.bl.dennyhalim.com"
add regexp="(pe2cku7pebkpgeko|p27dokhpz2n7nvgr|unocl45trpuoefft)" type=NXDOMAIN comment="malw.bl.dennyhalim.com"
add regexp="(twbers4hmi6dc65f|x5sbb5gesp6kzwsh|wjtqjleommc4z46i)" type=NXDOMAIN comment="malw.bl.dennyhalim.com"
add regexp="(xpcx6erilkjced3j|xrhwryizf5mui7a5)" type=NXDOMAIN comment="malw.bl.dennyhalim.com"
