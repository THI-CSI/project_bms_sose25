# BMS (Battery Management System)

A firmware project for managing and monitoring battery systems.

## Project Setup Instructions

Follow these steps to set up your development environment for this project:

> [!Note] 
> If you're using Windows, we recommend utilizing WSL.

---

### 1. Install Visual Studio Code

Download and install Visual Studio Code from the official website:

[https://code.visualstudio.com/](https://code.visualstudio.com/)

---

### 2. Install ARM Cross Compiler Toolchain

Install the ARM GCC cross compiler toolchain. You can do this by installing the appropriate package for your platform:

- **Windows without WSL (recommended):** [Arm GNU Toolchain Downloads](https://developer.arm.com/downloads/-/arm-gnu-toolchain-downloads)
- **Linux (Ubuntu):**  
```bash
sudo apt install gcc-arm-none-eabi
```
### 3. Install SEGGER J-Link

Download and install the SEGGER J-Link software and drivers: 

https://www.segger.com/downloads/jlink
### 4. Clone the GitHub Repository

Open a terminal or command prompt and run:
```bash
git clone --recurse-submodules https://github.com/THI-CSI/decentralized_iam_battery_data.git
cd bms
```

Additionally, update the `CC` and `OBJCOPY` variables in the `Makefile` to point to your installed ARM toolchain executable.

### 5. Open the Repository in VS Code

- Launch Visual Studio Code, then:

- Select `File` > `Open Folder`

- Browse to the cloned repository and open it

### 6. Additional Extensions

When you open the project in VS Code for the first time, you'll be prompted to install recommended extensions — go ahead and install all of them.

> [!NOTE]
> If you missed the prompt, you can still install them manually by opening the Extensions view and searching: `@recommended`

### 7. Install RA Device Support Files

- In your system's command prompt or start menu search bar:
Search for `> Renesas Support Files Manager`

- Launch it

- Under **Device Family**, select **RA**

- Install all support files for the RA family

## Building and Flashing the Image 
### Build
To compile the project, run the following command in the project root:
```bash
make clean 
make 
``` 

### Flash
1. Install the [Renesas Flash Programmer](https://www.renesas.com/en/software-tool/renesas-flash-programmer-programming-gui#overview) tool if you haven't already. 
2. Flash the compiled image using: 
```bash 
rfp-cli -device ra -tool jlink -file build/bms.srec -a -s 1M -vo 3.3 -if swd 
```

## Usage

To communicate with the device over Ethernet, you must first configure your network interface. Since only IPv4 is supported and DHCP is not available, you need to manually assign IP addresses. Additionally hostnames can be assigned in the `dns-server.conf` file.

### Linux

To set your Gateway IP address:
```bash
sudo ip addr add 192.168.0.3/24 dev <your_interface_name>
```
To assign your DNS server (no root needed)
```bash
sudo ip addr add 192.168.0.2/24 dev <your_interface_name>
```
To assign the server IP address:
```bash
sudo ip addr add 192.168.1.100/24 dev <your_interface_name>
```
Then, to start a server listener (e.g., using Netcat):
```bash
nc -l -p 12345 -s 192.168.1.100
```

To forward packets to the internet or the Docker network, you need to configure your firewall. In this example, I’ll use `iptables`, though you can use any firewall of your choice. Just make sure to watch for any rules that might block the packets.

```bash
# Enable forwarding of packets
sudo sysctl -w net.ipv4.ip_forward=1
# internal is the interface to the BMS
# external is the interface to the outside, e.g. internet or docker network
sudo iptables -A FORWARD -i <internal> -o <external> -j ACCEPT
sudo iptables -A FORWARD -i <external> -o <internal> -m state --state RELATED,ESTABLISHED -j ACCEPT 

> [!CAUTION]
> If you want to access the container you need to start the docker-compose files from the cloud and blockchain with podman-compose as root. The external interface is going to be podman0.

# If you want to access the internet you need to masquerade the IP from the BMS for routing purposes
sudo iptables -t nat -A POSTROUTING -o <external> -j MASQUERADE
```

### Windows

> [!Note] 
> These steps should be performed outside of WSL.

To set your IP address:
```powershell
netsh interface ip add address <your_interface_name> static 192.168.0.3 255.255.255.0
```

To assign the server IP address:
```powershell 
netsh interface ip add address <your_interface_name> static 192.168.1.100 255.255.255.0
```

Then, to start a server listener (e.g using Netcat):
```powershell
ncat -l 192.168.1.100 12345
```
