import importlib
import subprocess

def check_requirements():
    python_libraries = {
        'beautifulsoup4': 'bs4',
        'colorama': 'colorama',
        'prettytable': 'prettytable',
        'requests': 'requests',
        'tqdm': 'tqdm'
    }

    tools = {
        'curl': 'curl',
        'nmap': 'nmap',
        'nikto': 'nikto',
        'openssl': 'openssl',
        'searchsploit': 'searchsploit',
        'wafw00f': 'wafw00f',
        'whatweb': 'whatweb',
        'waybackurls': 'waybackurls',
        'sqlmap': 'sqlmap',
        'dirb': 'dirb',
        'ffuf': 'ffuf'
    }

    print("Checking Python libraries...")
    with open("requirements.txt", "r") as req_file:
        requirements = req_file.readlines()
        for library in requirements:
            library = library.strip()
            try:
                importlib.import_module(python_libraries[library])
                print(f"[+] {library} is installed")
            except ImportError:
                print(f"[-] {library} is not installed. Please install with 'pip install {library}'")

    print("\nChecking tools...")
    for tool in tools:
        result = subprocess.run(['which', tools[tool]], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.stdout:
            print(f"[+] {tool} is installed")
        else:
            print(f"[-] {tool} is not installed. Please install with your package manager, e.g., 'sudo apt install {tool}' or 'brew install {tool}'")

    print("\nPlease ensure all required Python libraries and tools are installed before running the script.")

if __name__ == "__main__":
    check_requirements()
