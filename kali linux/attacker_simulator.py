
import socket
import time
import random
import threading

TARGET = "192.168.56.20"

SOURCE_IPS = [
    "192.168.56.11",
    "192.168.56.12",
    "192.168.56.13",
    "192.168.56.14"
]

DELAY_MIN = 2
DELAY_MAX = 5


# Read server response until a particular prompt appears
def receive_until(sock, marker, timeout=8):
    sock.settimeout(timeout)
    data = b""

    while marker not in data:
        chunk = sock.recv(1024)

        if not chunk:
            break

        data += chunk

        if len(data) > 16000:
            break

    return data


# Connect using a particular source IP
def connect_to_server(source_ip, port):

    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    sock.settimeout(8)

    # Select the source IP for this connection
    sock.bind((source_ip, 0))

    sock.connect((TARGET, port))

    return sock


# Simulate an SSH-like attacker session
def ssh_attack(source_ip, username, commands):

    print(f"[{source_ip}] Connecting to SSH service")

    try:
        sock = connect_to_server(source_ip, 2222)

        receive_until(sock, b"login: ")
        sock.sendall((username + "\n").encode())

        receive_until(sock, b"Password: ")
        sock.sendall(b"simulation-password\n")

        receive_until(sock, b"$ ")

        for command in commands:

            print(f"[{source_ip}] Executing: {command}")

            sock.sendall((command + "\n").encode())

            response = receive_until(sock, b"$ ")

            if not response:
                break

            time.sleep(
                random.uniform(DELAY_MIN, DELAY_MAX)
            )

        # End the simulated session
        sock.sendall(b"exit\n")
        sock.close()

    except (OSError, socket.timeout) as error:
        print(f"[{source_ip}] SSH error: {error}")


# Simulate HTTP requests
def http_attack(source_ip):

    paths = [
        "/",
        "/admin",
        "/login",
        "/robots.txt"
    ]

    path = random.choice(paths)

    print(f"[{source_ip}] HTTP request: {path}")

    try:
        sock = connect_to_server(source_ip, 8080)

        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {TARGET}\r\n"
            "User-Agent: Honeypot-Simulator\r\n"
            "Connection: close\r\n\r\n"
        )

        sock.sendall(request.encode())
        sock.recv(4096)

        sock.close()

    except (OSError, socket.timeout) as error:
        print(f"[{source_ip}] HTTP error: {error}")


# Different attacker behaviour profiles
ATTACKERS = [
    {
        "name": "Reconnaissance attacker",
        "username": "admin",
        "commands": [
            "whoami",
            "pwd",
            "uname -a",
            "hostname",
            "ps",
            "ip addr"
        ]
    },

    {
        "name": "Credential discovery attacker",
        "username": "guest",
        "commands": [
            "whoami",
            "ls",
            "cat passwords.txt",
            "cat /etc/passwd",
            "cat /etc/shadow"
        ]
    },

    {
        "name": "Filesystem exploration attacker",
        "username": "support",
        "commands": [
            "pwd",
            "ls",
            "cd /etc",
            "ls",
            "cat hostname",
            "cd /home/admin",
            "sudo su"
        ]
    }
]


# One independent simulated attacker
def attacker_worker(source_ip, profile):

    print(
        f"\n[{source_ip}] Starting: {profile['name']}"
    )

    ssh_attack(
        source_ip,
        profile["username"],
        profile["commands"]
    )

    # Also visit the fake web service
    time.sleep(random.uniform(2, 4))

    http_attack(source_ip)

    print(f"[{source_ip}] Activity completed")


# Main simulation
def main():

    print("\n================================")
    print(" HONEYPOT ATTACKER SIMULATOR")
    print("================================")

    print("Target:", TARGET)

    threads = []

    for index, source_ip in enumerate(SOURCE_IPS):

        profile = ATTACKERS[index % len(ATTACKERS)]

        thread = threading.Thread(
            target=attacker_worker,
            args=(source_ip, profile)
        )

        threads.append(thread)
        thread.start()

    # Wait for all simulated attackers
    for thread in threads:
        thread.join()

    print("\nAll simulated attacker sessions completed.")


if __name__ == "__main__":
    main()
