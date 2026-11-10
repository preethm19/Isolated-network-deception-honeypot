
import socket
import threading

from fake_shell import execute_command
from database import log_event as db_log_event

LOG_FILE = "honeypot_events_v2.csv"
log_lock = threading.Lock()


# Central event logger - SQLite
def log_event(ip, source_port, dest_port,
              service, event, username="", details=""):

    db_log_event(
        source_ip=ip,
        source_port=source_port,
        destination_port=dest_port,
        service=service,
        event=event,
        username=username or None,
        details=details or None
    )

    print(
        f"[EVENT] {service} | {ip} | "
        f"Port {dest_port} | {event} | {details}"
    )


# Receive one line from the client
def receive_line(client):
    data = bytearray()

    while len(data) < 4096:
        char = client.recv(1)

        if not char or char == b"\n":
            break

        if char != b"\r":
            data.extend(char)

    return data.decode(errors="replace").strip()


# SSH-like interactive service
def handle_ssh(client, address, dest_port):
    ip, source_port = address
    username = ""

    try:
        client.settimeout(120)

        client.sendall(
            b"Welcome to Ubuntu SSH service (simulation)\n"
        )

        client.sendall(b"login: ")
        username = receive_line(client)

        client.sendall(b"Password: ")

        # Receive password, but never store it
        password = receive_line(client)

        log_event(
            ip, source_port, dest_port,
            "SSH", "LOGIN_ATTEMPT", username
        )

        # Simulate successful login
        client.sendall(
            b"\nWelcome to Ubuntu 22.04 LTS\n"
            b"Type 'help' to see available commands.\n\n"
        )

        current_dir = "/home/admin"

        while True:
            prompt = f"{username}@ubuntu:{current_dir}$ "
            client.sendall(prompt.encode())

            command = receive_line(client)

            if not command:
                continue

            # Record every command entered
            log_event(
                ip, source_port, dest_port,
                "SSH", "COMMAND_EXECUTED",
                username, command
            )

            # Execute only inside our fake filesystem
            output, current_dir = execute_command(
                command, current_dir, username
            )

            if output == "exit":
                client.sendall(b"Goodbye!\n")
                break

            if output:
                client.sendall((output + "\n").encode())

    except socket.timeout:
        print(f"[SSH] Session timed out: {ip}")

    except (ConnectionError, OSError) as error:
        print(f"[SSH ERROR] {error}")

    finally:
        client.close()


# HTTP-like service
def handle_http(client, address, dest_port):
    ip, source_port = address

    try:
        request = client.recv(4096).decode(
            errors="replace"
        )

        request_line = (
            request.splitlines()[0] if request else ""
        )

        log_event(
            ip, source_port, dest_port,
            "HTTP", "HTTP_REQUEST",
            details=request_line
        )

        print(f"[HTTP REQUEST] {request_line}")

        body = b"""
        <html>
        <body>
            <h1>Welcome to Ubuntu Web Server</h1>
            <p>Simulated honeypot service.</p>
        </body>
        </html>
        """

        response = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: text/html\r\n"
            + f"Content-Length: {len(body)}\r\n".encode()
            + b"Connection: close\r\n\r\n"
            + body
        )

        client.sendall(response)

    except (ConnectionError, OSError) as error:
        print(f"[HTTP ERROR] {error}")

    finally:
        client.close()


# Start a service on a given port
def start_service(port, service, handler):
    server = socket.socket(
        socket.AF_INET, socket.SOCK_STREAM
    )

    server.setsockopt(
        socket.SOL_SOCKET, socket.SO_REUSEADDR, 1
    )

    server.bind(("0.0.0.0", port))
    server.listen(10)

    print(f"[+] {service} listening on port {port}")

    while True:
        client, address = server.accept()

        ip, source_port = address

        log_event(
            ip, source_port, port,
            service, "CONNECTION"
        )

        thread = threading.Thread(
            target=handler,
            args=(client, address, port)
        )

        thread.start()


# Start SSH and HTTP services
threading.Thread(
    target=start_service,
    args=(2222, "SSH", handle_ssh),
    daemon=True
).start()

threading.Thread(
    target=start_service,
    args=(8080, "HTTP", handle_http),
    daemon=True
).start()


print("\nNetwork Honeypot running...")
threading.Event().wait()
