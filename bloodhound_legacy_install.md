## Created by https://github.com/Bilandzia

### Remove BloodHound Community from system
`sudo apt remove bloodhound`

### Download BloodHound Legacy
`wget https://github.com/SpecterOps/BloodHound-Legacy/releases/download/v4.3.1/BloodHound-linux-x64.zip`

### Unzip BloodHound Legacy
`unzip BloodHound-linux-x64.zip`

### Rename file to BloodHound and move to /usr/lib/
`mv ./BloodHound-linux-x64 /usr/lib/BloodHound`

### Add the following line to /.zshrc under "alias l = 'ls -CF'":
`alias bloodhound='/usr/lib/BloodHound/BloodHound --no-sandbox'`

### Save and quit, then type the following:
`source ~/.zshrc`
