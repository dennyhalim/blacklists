# this will get all dists files into /opt/blacklists-main/dist
cd /opt
rm dhbl.zip -f
wget https://github.com/dennyhalim/blacklists/archive/refs/heads/main.zip -O dhbl.zip
unzip main.zip "blacklists-main/dist/*"
rm dhbl.zip -f
