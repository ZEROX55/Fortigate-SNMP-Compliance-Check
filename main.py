import paramiko
from datetime import datetime
import os
import re
from bs4 import BeautifulSoup
import fw_ip_list
import credential

IP_LIST = fw_ip_list.ip_list

USERNAME = credential.USERNAME
PASSWORD = credential.PASSWORD
OUTPUT_DIR = "output"

# Compliance check command
SNMP_CMD = "show system snmp sysinfo"
COMMUNITY_CMD = "show system snmp community"
HOSTNAME_CMD = "show system global"

# Compliance check strings
SNMP_STATUS_CHECK = "set status enable"
COMMUNITY_NAME_CHECK = "RO_LZDMgmt"

def ssh_command(ip, username, password, command):
    """
    SSH to device and execute a command
    """
    try:
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_client.connect(hostname=ip, username=username, password=password, timeout=10)
        stdin, stdout, stderr = ssh_client.exec_command(command)
        output = stdout.read().decode("utf-8")
        ssh_client.close()
        return output
    except paramiko.AuthenticationException:
        return "Authentication failed."
    except paramiko.SSHException:
        return "Could not establish SSH connection."
    except paramiko.ChannelException:
        return "Could not open channel."
    except Exception as e:
        return f"Command fail. {str(e)}"

def generate_report(html_content):
    """
    Generate HTML report
    """
    date = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    report_name = f"Compliance_Report_{date}.html"
    report_path = os.path.join(OUTPUT_DIR, report_name)
    with open(report_path, "w") as file:
        file.write(html_content)
    return report_path

def main():
    html_table_header = "<tr><th>Hostname</th><th>IP Address</th><th>SSH Status</th><th>SNMP Status</th><th>Community Name</th><th>Missing IP</th><th>ACL IP</th></tr>"
    html_table_rows = ""
    for ip in IP_LIST:
        # SSH to firewall and get the config
        config = ssh_command(ip, USERNAME, PASSWORD, "show full-configuration")
        hostname_output = ssh_command(ip, USERNAME, PASSWORD, HOSTNAME_CMD)
        fw_hostname = extract_hostname(hostname_output)
        config_ips = "_"

        if "Command fail" in config:
            hostname = fw_hostname
            status = "Failed"
            snmp_status = "-"
            community_name = "-"
            missing_ip_list = "-"
            html_table_rows += f"<tr><td>{hostname}</td><td>{ip}</td><td>{status}</td><td>{snmp_status}</td><td>{community_name}</td><td>{missing_ip_list}</td><td>{config_ips}</td></tr>"
        else:
            hostname = fw_hostname
            status = "Success"
            snmp_output = ssh_command(ip, USERNAME, PASSWORD, SNMP_CMD)
            if SNMP_STATUS_CHECK in snmp_output:
                snmp_status = "Enabled"
                community_output = ssh_command(ip, USERNAME, PASSWORD, COMMUNITY_CMD)
                if COMMUNITY_NAME_CHECK not in community_output:
                    community_name = "Missing"
                else:
                    community_name = "RO_LZDmgmt"
                    # Extract IPs from config
                    config_ips = extract_ips_from_config(community_output)
                    print("Extracted IP addresses:", config_ips)
                    # Check if all IPs are in the allowed IP list
                    required_ips = [
                        "30.104.18.1",
                        "30.104.17.11",
                        "30.104.16.204",
                        "30.107.254.42",
                        "30.107.254.43",
                    ]

                    # Check if all required IPs are in the extracted IPs
                    if all(ip in config_ips for ip in required_ips):
                        missing_ip_list = "None"
                    else:
                        missing_ips = list(set(required_ips) - set(config_ips))
                        missing_ip_list = missing_ips
                    html_table_rows += f"<tr><td>{hostname}</td><td>{ip}</td><td>{status}</td><td>{snmp_status}</td><td>{community_name}</td><td>{missing_ip_list}</td><td>{config_ips}</td></tr>"
            else:
                snmp_status = "Disabled"
                community_name = "-"
                missing_ip_list = "-"
                html_table_rows += f"<tr><td>{hostname}</td><td>{ip}</td><td>{status}</td><td>{snmp_status}</td><td>{community_name}</td><td>{missing_ip_list}</td><td>{config_ips}</td></tr>"

    
    # Generate HTML report
    html_content = f"<html><head><title>Compliance Report</title></head><body><table border='1'>{html_table_header}{html_table_rows}</table></body></html>"
    report_path = generate_report(html_content)
    print(f"Report generated at {report_path}")

def extract_ips_from_config(community_output):
    ips = []
    for line in community_output.split("\n"):
        # Find lines starting with "set ip" and extract the IP address
        match = re.search(r"set ip (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) ", line)
        if match:
            ips.append(match.group(1))
    return ips

def extract_hostname(hostname_output):
    hostname = None
    for line in hostname_output.splitlines():
        match = re.search(r"set hostname \"?([\w-]+)\"?", line)
        if match:
            hostname = match.group(1)
            break
    return hostname


if __name__ == "__main__":
    main()
