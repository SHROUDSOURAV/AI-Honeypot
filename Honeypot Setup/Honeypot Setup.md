
# Honeypot Setup

- Below are the steps required to install the Cowrie Honeypot.
- We need to install the Cowrie Honeypot in the Linux system.

## Network Setup

- Keep 2 network adapters for the Linux VM.
- Adapter 1:
	- **Host-only** -> this is for creating a secluded home lab environment so that only the cowrie and our attack VM are present.
- Adapter 2:
	- **NAT** -> so that docker can download updates for our cowrie.


## Install Docker

```bash
sudo apt update # update the linux system
sudo apt install docker.io docker-compose -y # install docker
```

## Run Docker at Startup

```bash
sudo systemctl enable docker  
sudo systemctl start docker
```

## Cloning the Cowrie

```bash
git clone https://github.com/cowrie/cowrie.git
```

## Cowrie Configuration

### Config file Customization

- Copy the `etc/cowrie.cfg.dist` and move to `etc/cowrie.cfg`


```bash
cp etc/cowrie.cfg.dist etc/cowrie.cfg
```

- The `.dist` is a template file made by developers and the `.cfg` only file is our own custom file.
- When we run the cowrie the `.cfg` file overwrites the `.dist` one.


- **Modify**
	- Look for the below 2 lines in the file and modify them according to the below 2 values.

```
[ssh]  
listen_endpoints = tcp:2222:interface=0.0.0.0  
  
[telnet]  
enabled = true  
listen_endpoints = tcp:2223:interface=0.0.0.0
```

### iptables Configuration

- Cowrie is used to for SSH and telnet services and those services use port `22` and `23` respectively.
- So we need to reroute that traffic sent to those ports to our honeypot so that we can capture the commands and log them.
- Below `eth0` is used but your **Host-only** network adapter might be different so type the command cautiously.

```bash
sudo iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 22 -j REDIRECT --to-port 2222
sudo iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 23 -j REDIRECT --to-port 2223
```

### Install Cowrie Requirements 
`
```bash
python -m venv venv #Create python virtual environment
source venv/bin/activate #Activate the virtual environment
pip install -r requirements.txt
```


## Running Cowrie

### Cowrie Build

```bash
cd cowrie/docker
sudo docker compose build
sudo docker ps # verify cowrie build is running
```

### Run Cowrie

```bash
cd cowrie/docker
sudo docker compose up -d
```







