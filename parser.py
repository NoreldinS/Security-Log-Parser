import re
import json




LOG_FILE = "server.log"
#saves any alert messages to a json file
OUTPUT_FILE = "alertfile.json"
CountOutput = "count.json"
alert_list = []
count_list = []

LOG_PATTERN = r'(?P<date>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+(?P<level>\w+)\s+(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+(?P<message>.*)'


failed_attempts = {}
BruteCounter = 4

#keeps count of failed login attempts and returns "BRUTE" if the count exceeds the BruteCounter threshold
def check_brute(ip, message):
    if "failed login" in message.lower() or "401" in message:
        failed_attempts[ip] = failed_attempts.get(ip, 0) + 1

        if failed_attempts[ip] >= BruteCounter:
            return "BRUTE"
        
        
        

Attack_Sig = {
    # SQL injection = Tricking the database into giving away hidden data or bypassing logins
    "SQL Injection": [
        "' OR ", "1=1", "UNION SELECT", "DROP TABLE", "--", "SELECT * FROM"
    ],

    # path traversal = Sneaking past folder restrictions to read private server files
    "Path Traversal": [
        "../", "..\\", "/etc/passwd", "win.ini", "boot.ini"
    ],

    # cross-site Scripting = Injecting malicious code to hijack user sessions or popups
    "Cross-Site Scripting (XSS)": [
        "<script>", "javascript:", "onerror=", "onload=", "alert("
    ],

    # command injection = Forcing the server to execute system commands 
    "Command Injection": [
        "; whoami", "| nc", "`id`", "$(whoami)", "; cat /etc", "&& dir"
    ],

    # scanner probe = Automated hacker bots probing the site for easy weaknesses
    "Scanner Probe": [
        "nikto", "sqlmap", "nmap", "gobuster", "dirbuster"
    ]


}

#break down log line usinf regex into organized dictionary
def parse_log_line(line):
   match = re.search(LOG_PATTERN, line) # Search the line for regex pattern, stores a Match object with the found log if found
   if not match :
       return None
   return  match.groupdict() #stores match log object into organized dictionary
# parsed data names: "message", "ip", "date", "level"


#checks if there are attack patterns in passed message from log lines, returns the attack type if found
def detect_attacks(ip, message):
   if check_brute(ip, message) == "BRUTE":  
         attack_type = "Brute-force attack" # sends alert if attack type exists
         return attack_type
   for attack_type, patterns in Attack_Sig.items():
       for Attpattern in patterns:
           if Attpattern in message:
               return attack_type
                 
   return None

#prints the total log lines processed and total threats detected to the console
def printStats(a,b):
    print(f"Total log lines processed: {a}")
    print(f"Total threats detected: {b}")

#adds any alert messages to a json file
def addJson(ip,message,attacktype,date,level):
    alert = {
        "ip": ip,
        "message": message,
        "attack_type": attacktype,
        "date": date,
        "level": level
    }
    alert_list.append(alert)
    with open(OUTPUT_FILE, "w") as outfile:
        json.dump(alert_list, outfile, indent=4)

#adds the total log lines processed and total threats detected to a json file
def addJsonCount(total_count, threat_count):
    alert = {
        "total_log_lines": total_count,
        "total_threats_detected": threat_count
    }
    count_list.append(alert)
    with open(CountOutput, "w") as outfile:
        json.dump(count_list, outfile, indent=4)

#opens server log and reads each line and checks if the lines are valid and if they contain attacking patterns 
with open(LOG_FILE, "r") as file:
    count = 0
    coutnATT = 0
    for line in file: # reads all the lines in file
        parsed_lines = parse_log_line(line)
        if parsed_lines is not None: # stores true if regex pattern is found; checks if line is valid
            attack_type = detect_attacks(parsed_lines["ip"], parsed_lines["message"]) # checks if there are matching attack types
            count = count + 1
            if attack_type: # sends alert if attack type exists
                coutnATT = coutnATT + 1
                addJson(parsed_lines["ip"], parsed_lines["message"], attack_type, parsed_lines["date"], parsed_lines["level"])
                print(f"[ALERT] {attack_type} detected from IP: {parsed_lines['ip']}")
        elif parsed_lines is None: # sends alert if regex pattern is not found
            print(f"[ALERT] Invalid log line: {line.strip()}")
    
    addJsonCount(count, coutnATT) #adds the total log lines processed and total threats detected to a json file
    print(printStats(count, coutnATT)) # adds the total log lines processed and total threats detected to a json file









    