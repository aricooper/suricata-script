# hw2.md

## 1. SSH Management Port on FreeBSD

- **Keep existing VB NAT rule**  
  Host ↔ FreeBSD: port 22222 → guest 22 (unchanged)

- **Change SSHD to listen on a new port on FreeBSD**  
  Edit `/etc/ssh/sshd_config` on FreeBSD:
  ```diff
  -#Port 22
  +Port 22
  +Port 8022    # management SSH

- **Add port forwarding in VB**  
  In FreeBSD Network settings of Adapter 1  with the VM off:
  ```diff
  +Name: ssh mgmt
  +Host port: 8022
  +Guest port: 8022

- **Allow new mgmt port in PF**  
  Edit `/etc/pf.conf` on FreeBSD:
  ```diff
  +# Permit management SSH
  +pass in quick on $ext_if proto tcp from any to any port 8022 keep state

- **Forward SSH from FreeBSD to Ubuntu Server in PF**  
  Edit `/etc/pf.conf` on FreeBSD:
  ```diff
  +#redirect rules
  +rdr on $ext_if proto tcp from any to any port 22 -> $server port ssh
  +#forward ssh rules  
  +pass quick on $int_if proto tcp from any to $server port ssh keep state  
  +pass in quick on $ext_if proto tcp from any to $server port ssh keep state  

- **Install suricata on FreeBSD**  

  #### Installation  
  - Install the package and dependencies:  
    ```sh
    sudo pkg install -y suricata
    ```  
  - Enable Suricata at boot and configure it to run in IDS mode on em0
    ```sh
    sudo sysrc suricata_enable=YES
    sudo sysrc suricata_interface="em0"
    ```  
  - Start the Suricata service:  
    ```sh
    sudo service suricata start
    ```  

  #### Configuration  
  - Pull down and enable the latest rule sets:  
    ```sh
    sudo suricata-update
    sudo service suricata reload
    ```  
  - Edit `/usr/local/etc/suricata/suricata.yaml`, under `outputs:`, to ensure you have:  
    ```yaml
    - alert:
        enabled: yes
        filename: /var/log/suricata/alert.log

    - eve-log:
        enabled: yes
        filetype: regular
        filename: /var/log/suricata/eve.json
        types: [ alert, http, dns, tls, files, flow ]
    - netmap:
        - interface: ${WAN}
          copy-mode: tap
          copy-iface: ${LAN}
    ```  
  - Create (or append) a custom SMBGhost detection rule in `local.rules`:  
    ```rules
    alert tcp any any -> any 445 (
      msg:"SMBGhost CVE-2020-0796 attempt";
      flow:established,to_server;
      content:"|FF 53 4D 42 40|"; depth:5;
      byte_test:1,>,0x7,13,offset 13;
      reference:cve,2020-0796;
      sid:1000001; rev:1;
    )
    ```  
  - Reload Suricata so it picks up all changes:  
    ```sh
    sudo service suricata reload
    ```  

  #### Testing  
  - **Port scan alert**  
    ```sh
    sudo nmap -sS -Pn -p22,80 192.168.33.63
    grep scan /var/log/suricata/eve.json
    ```  
  - **SMBGhost PoC**  
    ```sh
    python3 CVE-2020-0796.py 192.168.33.63
    tail -n 20 /var/log/suricata/alert.log
    ```  
    You should see an entry tagged `SMBGhost CVE-2020-0796 attempt` in both `alert.log` and `eve.json`.  
 

  

