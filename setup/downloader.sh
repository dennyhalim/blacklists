# this will get all dists files into /opt/blacklists-main/dist
cd /opt
rm dhbl.zip -f
curl -o dhbl.zip https://codeload.github.com/dennyhalim/blacklists/zip/refs/heads/main
unzip -o dhbl.zip "blacklists-main/dist/*"
rm dhbl.zip -f
