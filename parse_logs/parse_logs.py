"""parse_logs.py - parsing component of logalyzer.

This script includes classes and functions for parsing authentication logs and extracting relevant information.
"""

import re
import gzip


class Log:
    """
    Represents a log object.

    This object is stored in a dictionary with the user as the key and Log as the value.
    The Log object includes logs, fails, successes, logged IPs, and commands used.
    """

    def first_date(self):
        """
        Returns the date of the first log entry.

        If logs exist, it iterates through them to find the first valid date.

        Returns:
            datetime: The date of the first log entry.
        """
        if len(self.logs) > 0:
            date = None
            i = 0
            while i < len(self.logs) and date is None:
                date = parse_date(self.logs[i])
                i += 1
            return date

    def last_date(self):
        """
        Returns the date of the last log entry.

        Returns:
            datetime: The date of the last log entry.
        """
        if len(self.logs) > 0:
            return parse_date(self.logs[-1])

    def __init__(self, usr):
        """
        Initializes a Log object.

        Args:
            usr (str): The user associated with the log.
        """
        self.usr = usr
        self.logs = []
        self.fail_logs = []
        self.succ_logs = []
        self.ips = []
        self.commands = []


def parse_usr(line):
    """
    Parses the user from a log line.

    Args:
        line (str): The log line.

    Returns:
        str: The parsed user.
    """
    usr = None
    if "Accepted password for" in line:
        usr = re.search(r"(\bfor\s)(\w+)", line)
    elif "sudo:" in line:
        usr = re.search(r"(sudo:\s+)(\w+)", line)
    elif "authentication failure" in line:
        usr = re.search(r"USER=\w+", line)
    elif "for invalid user" in line:
        usr = re.search(r"(\buser\s)(\w+)", line)
    return usr.group(2) if usr is not None else None


def parse_ip(line):
    """
    Parses an IP address from a log line.

    Args:
        line (str): The log line.

    Returns:
        str: The parsed IP address.
    """
    usr_ip = re.search(r"(\bfrom\s)(\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b)", line)
    return usr_ip.group(2) if usr_ip is not None else None


def parse_date(line):
    """
    Parses a date from a log line.

    Args:
        line (str): The log line.

    Returns:
        str: The parsed date.
    """
    date = re.search(
        r"^[A-Za-z]{3}\s*[0-9]{1,2}\s[0-9]{1,2}:[0-9]{2}:[0-9]{2}", line
    )
    return date.group(0) if date is not None else None


def parse_cmd(line):
    """
    Parses a command from a log line.

    Args:
        line (str): The log line.

    Returns:
        str: The parsed command.
    """
    cmd = re.search(r"(\bCOMMAND=)(.+?$)", line)
    return cmd.group(2) if cmd is not None else None


def parse_logs(auth_log):
    """
    Parses authentication logs and returns a dictionary of Log objects.

    Args:
        auth_log (str): Path to the authentication log file.

    Returns:
        dict: Dictionary with users as keys and Log objects as values.
    """
    logs = {}
    f_f = None
    try:
        with gzip.open(auth_log, "r") if ".gz" in auth_log else open(
            auth_log, "r"
        ) as f_f:
            log = f_f.read()
    except FileNotFoundError as e_e:
        print(f"[-] Error opening '{auth_log}': {e_e}")
        return None

    for line in log.split("\n"):
        if "Accepted password for" in line:
            usr = parse_usr(line)
            if usr not in logs:
                logs[usr] = Log(usr)

            usr_ip = parse_ip(line)
            if usr_ip not in logs[usr].ips:
                logs[usr].ips.append(usr_ip)
            logs[usr].succ_logs.append(line.rstrip("\n"))
            logs[usr].logs.append(line.rstrip("\n"))

        elif "Failed password for" in line:
            usr = parse_usr(line)
            if usr not in logs:
                logs[usr] = Log(usr)

            usr_ip = parse_ip(line)
            if usr_ip not in logs[usr].ips:
                logs[usr].ips.append(usr_ip)
            logs[usr].fail_logs.append(line.rstrip("\n"))
            logs[usr].logs.append(line.rstrip("\n"))

        elif ":auth): authentication failure;" in line:
            usr = re.search(r"(\blogname=)(\w+)", line)
            if usr is not None:
                usr = usr.group(2)
            if "(sshd:auth)" in line:
                usr = parse_usr(line)
                if usr not in logs:
                    logs[usr] = Log(usr)
                logs[usr].ips.append(parse_ip(line))
            else:
                if usr not in logs:
                    logs[usr] = Log(usr)
            logs[usr].fail_logs.append(line.rstrip("\n"))
            logs[usr].logs.append(line.rstrip("\n"))

        elif "sudo:" in line:
            usr = parse_usr(line)
            if usr not in logs:
                logs[usr] = Log(usr)

            cmd = parse_cmd(line)
            if cmd is not None:
                if cmd not in logs[usr].commands:
                    logs[usr].commands.append(cmd)
            logs[usr].logs.append(line.rstrip("\n"))
    return logs
