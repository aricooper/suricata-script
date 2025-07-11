#!/bin/sh
set -e

# The following features are added:
# - switching (internal to the network) via FreeBSD pf
# - DHCP/DNS via dnsmasq
# - firewall & NAT via PF
# - configure firewall for ssh passthrough to ubuntu server
# - install & configure suricata

# Interface names
WAN="em0"
LAN="em1"

# 1) Install packages if missing
PKGS="
  dnsmasq shfmt groff eza tmux zsh vim emacs git gdb bat figlet filters cowsay
  lolcat fontforge doxygen gawk hexyl sipcalc direnv wireshark tcpdump ruby
  ruby32-gems pyenv atuin fastfetch sunwait diff-so-fancy btop autojump fzf cmake
"
for p in $PKGS; do
  if ! pkg info -e "$p" >/dev/null 2>&1; then
    sudo pkg install -y "$p"
  fi
done

# 2) Install Ruby gems if missing
for g in colorls mdless; do
  if ! gem list -i "$g" >/dev/null 2>&1; then
    sudo gem install "$g"
  fi
done

# 3) Enable IP forwarding at boot
sudo sysrc gateway_enable=YES

# Also set it immediately
grep -qxF 'net.inet.ip.forwarding=1' /etc/sysctl.conf \
  || echo 'net.inet.ip.forwarding=1' | sudo tee -a /etc/sysctl.conf
sudo sysctl net.inet.ip.forwarding=1

# 4) Configure LAN IP once
DESIRED_IP="192.168.33.1"
if ! ifconfig "$LAN" | grep -q "inet $DESIRED_IP"; then
  sudo ifconfig "$LAN" inet "$DESIRED_IP" netmask 255.255.255.0 up
fi
# Persist in rc.conf
sudo sysrc ifconfig_${LAN}="inet ${DESIRED_IP} netmask 255.255.255.0"

# Enable promiscuous if not already
if ! ifconfig "$LAN" | grep -q PROMISC; then
  sudo ifconfig "$LAN" promisc
fi

# 5) Enable dnsmasq at boot
sudo sysrc dnsmasq_enable=YES

# 6) Templated PF config (always overwritten to keep it clean)
echo "
ext_if=\"${WAN}\"
int_if=\"${LAN}\"

icmp_types = \"{ echoreq unreach }\"
services   = \"{ ssh domain http ntp https }\"
server     = \"192.168.33.63\"

#options
set skip on lo0

#normalization
scrub in all fragment reassemble max-mss 1440

#NAT rules
nat on \$ext_if from \$int_if:network to any -> (\$ext_if)

#redirect rules
rdr on \$ext_if proto tcp from any to any port 22 -> \$server port ssh

#forward ssh rules
pass quick on \$int_if proto tcp from any to \$server port ssh keep state
pass in quick on \$ext_if proto tcp from any to \$server port ssh keep state

#permit management SSH
pass in quick on \$ext_if proto tcp from any to any port 8022 keep state

#blocking rules
antispoof quick for \$ext_if
block in quick log on egress from <rfc6890>
block return out quick log on egress to <rfc6890>
block log all

#general pass rules
pass in quick on \$int_if inet proto udp from any port = bootpc to 255.255.255.255 port = bootps keep state label \"allow access to DHCP server\"
pass in quick on \$int_if inet proto udp from any port = bootpc to \$int_if:network port = bootps keep state label \"allow access to DHCP server\"
pass out quick on \$int_if inet proto udp from \$int_if:0 port = bootps to any port = bootpc keep state label \"allow access to DHCP server\"

pass in quick on \$ext_if inet proto udp from any port = bootps to \$ext_if:0 port = bootpc keep state label \"allow access to DHCP client\"
pass out quick on \$ext_if inet proto udp from \$ext_if:0 port = bootpc to any port = bootps keep state label \"allow access to DHCP client\"

pass in on \$ext_if proto tcp to port { ssh } keep state (max-src-conn 15, max-src-conn-rate 3/1, overload <bruteforce> flush global)
pass out on \$ext_if proto { tcp, udp } to port \$services
pass out on \$ext_if inet proto icmp icmp-type \$icmp_types
pass in on \$int_if from \$int_if:network to any
pass out on \$int_if from \$int_if:network to any
" | sudo tee /etc/pf.conf

# 7) Start dnsmasq if not running
if ! pgrep -x dnsmasq >/dev/null 2>&1; then
  sudo service dnsmasq start
fi

# 8) Enable PF at boot, but start only if not already running
sudo sysrc pf_enable=YES pflog_enable=YES
if ! pfctl -si | grep -q 'Status: Enabled'; then
  sudo service pf start
fi
sudo pfctl -f /etc/pf.conf

# 9) Suricata install & IDS configuration
if ! pkg info -e suricata >/dev/null 2>&1; then
  sudo pkg install -y suricata
  sudo sysrc suricata_enable=YES
  sudo sysrc suricata_netmap=YES

  sudo sysrc suricata_flags="-c /usr/local/etc/suricata/suricata.yaml -i ${WAN} -i ${LAN}"
  sudo service suricata start
fi

# Update rules
sudo suricata-update

# Ensure log directory exists
sudo mkdir -p /var/log/suricata

# Enable alert.log and eve.json outputs
SURICATA_YAML=/usr/local/etc/suricata/suricata.yaml

#–– Enable file logging only if not already enabled
if ! grep -A1 '^\s*-\s*file:' "$SURICATA_YAML" | grep -q '^\s*enabled:\s*yes'; then
  sudo sed -i '' '/- file:/!b;n;c\          enabled: yes' "$SURICATA_YAML"
fi

#–– Enable eve-log only if not already enabled
if ! grep -A1 '^\s*-\s*eve-log:' "$SURICATA_YAML" | grep -q '^\s*enabled:\s*yes'; then
  sudo sed -i '' '/- eve-log:/!b;n;c\        enabled: yes' "$SURICATA_YAML"
fi

#–– Configure eve-log filename only if not already set
if ! grep -A1 'filename: eve.json' "$SURICATA_YAML" | grep -q '^\s*filename:\s*eve.json'; then
  sudo sed -i '' '/filename: eve.json/!b;n;c\        filename: eve.json' "$SURICATA_YAML"
fi

#-- Enable netmap for inline protection
if ! grep -q '^netmap:' "$SURICATA_YAML"; then
  sudo tee -a "$SURICATA_YAML" > /dev/null <<EOF
netmap:
  - interface: ${WAN}
    copy-mode: tap
    copy-iface: ${LAN}
EOF
fi

# Add SMBGhost detection rule if missing
LOCAL_RULES=/usr/local/etc/suricata/rules/local.rules
sudo mkdir -p "$(dirname "$LOCAL_RULES")"
grep -q 'SMBGhost CVE-2020-0796' "$LOCAL_RULES" || cat <<'RUL' | sudo tee -a "$LOCAL_RULES"
alert tcp any any -> any 445 (
  msg:"SMBGhost CVE-2020-0796 attempt";
  flow:established,to_server;
  content:"|FF 53 4D 42 40|"; depth:5;
  byte_test:1,>,0x7,13,offset 13;
  reference:cve,2020-0796;
  sid:1000001; rev:1;
)
RUL

# Reload Suricata to apply config & rules
sudo service suricata restart

# 10) SSH configuration: enable root and ports
SSH_CONF=/etc/ssh/sshd_config

# Permit root login if needed
if ! grep -q '^PermitRootLogin yes' "$SSH_CONF"; then
  sudo sed -i '' 's@^#PermitRootLogin no@PermitRootLogin yes@' "$SSH_CONF"
fi

# Ensure default Port 22 is active
if ! grep -q '^Port 22' "$SSH_CONF"; then
  sudo sed -i '' 's@^#Port 22@Port 22@' "$SSH_CONF"
fi

# Add Port 8022 if missing
if ! grep -q '^Port 8022' "$SSH_CONF"; then
  echo 'Port 8022' | sudo tee -a "$SSH_CONF"
fi

# Restart sshd to apply changes
sudo service sshd restart

# 11) Record interfaces’ MACs (overwrites ethers.txt)
hostname | tr -d '
' > ethers.txt
echo -n ',' >> ethers.txt
ifconfig "$WAN" | awk '/ether/ {print "'"$WAN""←""$2""}' | tr -d '
' >> ethers.txt
echo -n ',' >> ethers.txt
ifconfig "$LAN" | awk '/ether/ {print "'"$LAN""→""$2""}' >> ethers.txt

# 12) Python setup (will skip if version already set)
if ! pyenv versions | grep -q '3.12.6'; then
  pyenv install 3.12.6
fi
pyenv global 3.12.6
eval "$(pyenv init -)"

pip install --upgrade pip requests python-dateutil

# 13) Developer tools (clone only once)
[ -f "$HOME/antigen.zsh" ] || curl -L git.io/antigen > "$HOME/antigen.zsh"
[ -d "$HOME/.tmux/plugins/tpm" ]  || git clone https://github.com/tmux-plugins/tpm "$HOME/.tmux/plugins/tpm"
[ -d "$HOME/.oh-my-zsh" ]         || git clone https://github.com/ohmyzsh/ohmyzsh.git "$HOME/.oh-my-zsh"
[ -d "$HOME/clones/astral" ]      || mkdir -p "$HOME/clones" && git clone https://github.com/sffjunkie/astral.git "$HOME/clones/astral"
[ -f "$HOME/.zshrc.local" ]       || curl http://web.cecs.pdx.edu/~dmcgrath/setup_freebsd.tar.bz2 | tar xjvf - -C "$HOME"

# 14) Default shell
if [ "$SHELL" != "/usr/local/bin/zsh" ]; then
  sudo chsh -s /usr/local/bin/zsh "$LOGNAME"
fi

# 15) Git config check
if ! git config --global user.name >/dev/null; then
  echo "Please set your git user.name and user.email:"
  echo "  git config --global user.name  \"Ari Cooper\""
  echo "  git config --global user.email \"acoop@pdx.edu\""
fi

# 16) Git color & pager settings
git config --global core.pager              "diff-so-fancy | less --tabs=4 -RFX"
git config --global interactive.diffFilter  "diff-so-fancy --patch"
git config --global color.ui                true
git config --global color.diff-highlight.oldNormal    "red bold"
git config --global color.diff-highlight.oldHighlight "red bold 52"
git config --global color.diff-highlight.newNormal    "green bold"
git config --global color.diff-highlight.newHighlight "green bold 22"
git config --global color.diff.meta                     "11"
git config --global color.diff.frag                     "magenta bold"
git config --global color.diff.func                     "146 bold"
git config --global color.diff.commit                   "yellow bold"
git config --global color.diff.old                      "red bold"
git config --global color.diff.new                      "green bold"
git config --global color.diff.whitespace               "red reverse"

echo "SETUP IS COMPLETE"
echo "You may run this script multiple times without issues."
echo "You may need to run the following commands to finish setting up your environment:"
echo " cd .antigen/bundles/romkatv/powerlevel10k/gitstatus"
echo " ./build -s -w"
