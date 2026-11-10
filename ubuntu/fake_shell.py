# Fake Linux environment for the honeypot

FAKE_FILESYSTEM = {
    "/": {
        "home": "DIR",
        "etc": "DIR",
        "var": "DIR"
    },

    "/home": {
        "admin": "DIR"
    },

    "/home/admin": {
        "Desktop": "DIR",
        "Documents": "DIR",
        "Downloads": "DIR",
        "passwords.txt": "admin: ********\nroot: ********",
        "notes.txt": "System maintenance scheduled for tomorrow."
    },

    "/etc": {
        "hostname": "ubuntu-server",
        "os-release": "Ubuntu 22.04 LTS"
    },

    "/var": {
        "log": "DIR"
    },

    "/var/log": {
        "system.log": "System started successfully."
    }
}


def list_directory(path):
    return FAKE_FILESYSTEM.get(path, {})


def read_file(path):
    parent, _, filename = path.rpartition("/")

    if not parent:
        parent = "/"

    return FAKE_FILESYSTEM.get(parent, {}).get(filename)


def normalize_path(current, target):
    if target.startswith("/"):
        return target.rstrip("/") or "/"

    if target == "..":
        return current.rpartition("/")[0] or "/"

    if target == ".":
        return current

    return (current.rstrip("/") + "/" + target).replace("//", "/")


def execute_command(command, current_dir, username):
    parts = command.strip().split()

    if not parts:
        return "", current_dir

    cmd = parts[0]

    if cmd == "help":
        return "Available: help, whoami, pwd, ls, cd, cat, uname, hostname, exit", current_dir

    elif cmd == "whoami":
        return username, current_dir

    elif cmd == "pwd":
        return current_dir, current_dir

    elif cmd == "ls":
        items = list_directory(current_dir)
        return "  ".join(items.keys()) or "Directory is empty", current_dir

    elif cmd == "cd":
        target = parts[1] if len(parts) > 1 else "/home/admin"
        new_path = normalize_path(current_dir, target)

        if new_path in FAKE_FILESYSTEM:
            return "", new_path

        return "No such directory", current_dir

    elif cmd == "cat":
        if len(parts) < 2:
            return "Usage: cat filename", current_dir

        file_path = normalize_path(current_dir, parts[1])
        content = read_file(file_path)

        if content is not None and content != "DIR":
            return content, current_dir

        return "File not found", current_dir

    elif cmd == "uname":
        return "Linux ubuntu-server 5.15.0-generic x86_64", current_dir

    elif cmd == "hostname":
        return "ubuntu-server", current_dir

    elif cmd == "exit":
        return "exit", current_dir

    return f"{cmd}: command not found", current_dir
