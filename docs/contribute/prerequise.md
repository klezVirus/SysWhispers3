# Prerequise
SysWhispers3 does not need any kind of preinstallation to run other than python3 installed on the system.

## Python3 on Debian based systems
On Debian-based linux systems (Debian / Ubuntu / Kali), installing python3 and pip3 is like
```bash
apt install python3 python3-pip
```

## Python3 on Windows systems
A complete guide can be found on [python.ord](https://docs.python-guide.org/starting/install3/win/) or more detailed on [phoenixap.com](https://phoenixnap.com/kb/how-to-install-python-3-windows)
1. Download [python installer](https://www.python.org/downloads/windows/)
2. Ensure pip is installed
```bash
pip -V
```

## Poetry installation
This project works using poetry as a python venv. You could install it using then [online doc](https://python-poetry.org/docs/#installation) or:

### For Linux, macOS or Windows (WSL)
```bash
curl -sSL https://install.python-poetry.org | python3 -
```

### For Windows (Powershell)
```bash
(Invoke-WebRequest -Uri https://install.python-poetry.org -UseBasicParsing).Content | py -
```
**Note:** If you have installed Python through the Microsoft Store, replace py with python in the command above.