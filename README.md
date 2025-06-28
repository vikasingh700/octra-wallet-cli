<h2 align=center>Create octra wallet using CLI</h2>

## Installation
- Open any Linux based terminal, you can use VPS / WSL (On windows) or simply you can use virtual IDE as well
- If you don't have any VPS or not have WSL installed in your Windows, then simply go for virtual IDE
- One virtual IDE, I use the most is [Github Codespaces](https://github.com/codespaces), visit this link and choose a blank template
> [!NOTE]
> If you already have 2 templates opened in github codespace, in that case you need to delete one before opening another one
- Now install `curl` command first
```
command -v curl >/dev/null 2>&1 || { sudo apt-get update && sudo apt-get install -y curl; }
```
- Now use the below command to generate your octra wallet
```
curl -sSL https://raw.githubusercontent.com/zunxbt/octra-wallet-cli/refs/heads/main/start.sh -o start.sh && chmod +x start.sh && ./start.sh
```
