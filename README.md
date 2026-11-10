# Network Honeypot and Attack Monitoring System

A local, isolated network honeypot built with Python, SQLite, Flask, and
Streamlit. It simulates SSH-like and HTTP-like services, presents a fake
Linux shell and filesystem, records interactions, applies
behaviour-based detection rules, and displays activity in a dashboard.

This is an educational **low-interaction honeypot** for a controlled
VirtualBox lab. It is not a production-grade SSH server, intrusion
prevention system, or replacement for a mature honeypot such as Cowrie.

## Table of Contents

1.  [Project Overview](#1-project-overview)
2.  [Features](#2-features)
3.  [Architecture](#3-architecture)
4.  [Technology Stack](#4-technology-stack)
5.  [Lab Environment and Network
    Plan](#5-lab-environment-and-network-plan)
6.  [VirtualBox Network
    Configuration](#6-virtualbox-network-configuration)
7.  [Configure the Virtual Machines](#7-configure-the-virtual-machines)
8.  [Install Dependencies](#8-install-dependencies)
9.  [Project Structure](#9-project-structure)
10. [SQLite Database](#10-sqlite-database)
11. [Run the Honeypot](#11-run-the-honeypot)
12. [Run the Attacker Simulator](#12-run-the-attacker-simulator)
13. [Detection Engine](#13-detection-engine)
14. [Flask API](#14-flask-api)
15. [Streamlit Dashboard on macOS](#15-streamlit-dashboard-on-macos)
16. [Wireshark Traffic Analysis](#16-wireshark-traffic-analysis)
17. [Demonstration Workflow](#17-demonstration-workflow)
18. [Troubleshooting](#18-troubleshooting)
19. [Security Considerations and
    Limitations](#19-security-considerations-and-limitations)
20. [Future Enhancements](#20-future-enhancements)

------------------------------------------------------------------------

## 1. Project Overview

A honeypot is a decoy system or service designed to attract and observe
potentially malicious activity. It provides a controlled target where
interactions can be recorded and analysed without exposing a real
production service.

This project implements a **low-interaction honeypot** with two
simulated services:

-   An SSH-like interactive service on TCP port `2222`.
-   An HTTP-like service on TCP port `8080`.

The SSH-like service accepts dummy credentials and presents a simulated
terminal. Commands such as `whoami`, `pwd`, `ls`, `cd`, `cat`, `uname`,
and `hostname` are handled by Python code against an in-memory fake
filesystem. They are not executed by the host operating system.

Connections, login attempts, commands, and HTTP requests are stored in
SQLite. A Python detection engine analyses the records for selected
suspicious patterns. A Flask API exposes the records to a Streamlit
dashboard running on macOS.

All testing is intended to take place inside an isolated VirtualBox lab.

## 2. Features

### Honeypot services

-   TCP listener for an SSH-like interaction on port `2222`.
-   TCP listener for a simple HTTP-like interaction on port `8080`.
-   Concurrent connection handling using Python threads.
-   Fake login flow and simulated shell prompt.
-   In-memory fake filesystem and command responses.
-   Basic HTTP request capture.

### Logging and storage

-   Centralised event logging through `database.py`.
-   SQLite persistence in `honeypot.db`.
-   UTC ISO 8601 timestamps.
-   Indexes on source IP, timestamp, and event type.
-   Passwords are not stored in the event database.

### Detection and monitoring

-   Repeated login-attempt detection.
-   Possible port-scan detection.
-   Command-pattern analysis in the broader reporting/dashboard
    implementation.
-   Flask API endpoints for health checks and event retrieval.
-   Streamlit dashboard with automatic refresh.
-   Wireshark packet inspection on Kali Linux.

## 3. Architecture

The lab uses three environments:

1.  **Kali Linux VM:** attacker/test machine. Runs the traffic simulator
    and can be used for manual testing and packet inspection.
2.  **Ubuntu VM:** honeypot host. Runs the simulated services, SQLite
    database, detection engine, and Flask API.
3.  **macOS host:** runs the Streamlit dashboard and accesses the Ubuntu
    API over a VirtualBox host-only network.

``` text
                  ISOLATED VIRTUALBOX LAB
┌───────────────────────────────────────────────────────────────┐
│                                                               │
│  Kali Linux VM                                                 │
│  Attacker / Traffic Simulator                                  │
│  192.168.56.10, .11, .12, .13                                  │
│             │                                                 │
│             │ Internal Network: honeynet                      │
│             ▼                                                 │
│  Ubuntu VM                                                     │
│  ├── SSH-like service : TCP 2222                               │
│  ├── HTTP-like service: TCP 8080                               │
│  ├── Fake shell and filesystem                                 │
│  ├── SQLite: honeypot.db                                       │
│  ├── Detection engine                                          │
│  └── Flask API: TCP 5000                                       │
│                                                               │
└───────────────────────────────────────────────────────────────┘
                              │
                              │ Host-only network
                              │ Ubuntu: 192.168.57.2
                              ▼
                    macOS Host
                    └── Streamlit Dashboard
                        └── Flask API client
```

### Network separation

  -------------------------------------------------------------------------
  Network                 Purpose                 Example addresses
  ----------------------- ----------------------- -------------------------
  Internal Network        Kali-to-Ubuntu honeypot Kali
  (`honeynet`)            traffic                 `192.168.56.10`--`.13`,
                                                  Ubuntu `192.168.56.20`

  Host-only Network       macOS-to-Ubuntu API     Ubuntu `192.168.57.2`
                          communication           
  -------------------------------------------------------------------------

Ubuntu has two network interfaces:

-   `enp0s8`: internal honeynet interface, `192.168.56.20/24`.
-   `enp0s9`: host-only management/API interface, `192.168.57.2/24`.

Kali uses `eth0` for the internal honeynet network.

The extra Kali addresses are IP aliases on the same VM. They let the
simulator generate events with different apparent source IP addresses,
but they do **not** represent separate physical attackers.

## 4. Technology Stack

  Component                Technology
  ------------------------ -----------------------------------
  Virtualisation           Oracle VirtualBox
  Attacker/test VM         Kali Linux
  Honeypot VM              Ubuntu
  Programming language     Python 3
  Network communication    Python `socket`
  Concurrent connections   Python `threading`
  Fake terminal            Custom Python command interpreter
  Database                 SQLite
  Database access          Python `sqlite3`
  API                      Flask
  Dashboard                Streamlit
  Data handling            pandas
  Dashboard refresh        streamlit-autorefresh
  Packet inspection        Wireshark
  Manual TCP testing       Netcat (`nc`)
  Connectivity testing     `ping`

## 5. Lab Environment and Network Plan

  --------------------------------------------------------------------------
  Machine           Interface         Address              Purpose
  ----------------- ----------------- -------------------- -----------------
  Kali Linux        `eth0`            `192.168.56.10/24`   Main attacker
                                                           address

  Kali Linux        `eth0` alias      `192.168.56.11/24`   Simulated source

  Kali Linux        `eth0` alias      `192.168.56.12/24`   Simulated source

  Kali Linux        `eth0` alias      `192.168.56.13/24`   Simulated source

  Ubuntu            `enp0s8`          `192.168.56.20/24`   Honeypot services

  Ubuntu            `enp0s9`          `192.168.57.2/24`    Host-only API
                                                           access

  macOS             Host-only         Assigned by          Dashboard client
                    interface         VirtualBox           
  --------------------------------------------------------------------------

These are the addresses used in this lab. If VirtualBox assigns a
different host-only address in another installation, update the API URL
and interface configuration accordingly.

## 6. VirtualBox Network Configuration

Configure adapters from each VM's **Settings → Network** panel.

### Kali Linux VM

-   Adapter 1: Internal Network.
-   Network name: `honeynet`.
-   Adapter enabled and cable connected.

### Ubuntu VM

-   Adapter 1: Internal Network.
-   Network name: `honeynet`.
-   Adapter 2: Host-only Adapter.
-   Select the VirtualBox host-only interface.
-   Ensure both adapters are enabled and cable connected.

Do not use Bridged Adapter for this project. The internal network keeps
attacker traffic within the lab. The host-only adapter provides a
separate path for the macOS dashboard to access Flask.

### Verify interfaces

On Kali:

``` bash
ip addr
ip route
```

On Ubuntu:

``` bash
ip addr
ip route
```

Confirm the interface names and addresses before changing network
configuration.

## 7. Configure the Virtual Machines

### 7.1 Kali: persistent source IP addresses

Kali uses multiple addresses on `eth0` so the simulator can bind
outgoing connections to different source IPs.

Inspect NetworkManager profiles:

``` bash
nmcli connection show
```

Identify the profile associated with `eth0`. Replace `<connection-name>`
with the actual profile name:

``` bash
sudo nmcli connection modify "<connection-name>" \
  ipv4.method manual \
  ipv4.addresses "192.168.56.10/24,192.168.56.11/24,192.168.56.12/24,192.168.56.13/24" \
  ipv4.never-default yes
```

Apply the profile:

``` bash
sudo nmcli connection down "<connection-name>"
sudo nmcli connection up "<connection-name>"
```

Verify:

``` bash
ip addr show eth0
```

The four addresses should appear on the interface. NetworkManager
profile names vary, so use the name returned by `nmcli connection show`.

### 7.2 Ubuntu: internal honeynet address

The Ubuntu internal interface is `enp0s8`. A Netplan configuration for
this interface uses a static address and does not require a default
gateway on the isolated honeynet network.

Example:

``` yaml
network:
  version: 2
  ethernets:
    enp0s8:
      dhcp4: false
      addresses:
        - 192.168.56.20/24
```

Netplan files are normally stored in `/etc/netplan/`. Edit the
appropriate existing YAML file rather than creating conflicting
definitions.

Apply and verify:

``` bash
sudo netplan try
sudo netplan apply
ip addr show enp0s8
```

### 7.3 Ubuntu: host-only address

Configure `enp0s9` with the host-only address:

``` yaml
network:
  version: 2
  ethernets:
    enp0s9:
      dhcp4: false
      addresses:
        - 192.168.57.2/24
```

If both interfaces are configured in one Netplan file, put both under
the same `network.ethernets` section. Do not create duplicate top-level
`network` sections.

Apply and verify:

``` bash
sudo netplan try
sudo netplan apply
ip addr show enp0s9
```

### 7.4 Test connectivity

From Kali:

``` bash
ping 192.168.56.20
```

From Ubuntu:

``` bash
ping 192.168.56.10
```

From macOS:

``` bash
ping 192.168.57.2
```

Successful ping tests confirm basic IP connectivity, not
application-port availability.

## 8. Install Dependencies

### Ubuntu honeypot VM

Install Python, pip, SQLite, and useful network tools:

``` bash
sudo apt update
sudo apt install python3 python3-pip sqlite3 netcat-openbsd
```

The core honeypot uses Python standard-library modules such as `socket`,
`threading`, `sqlite3`, and `datetime`.

Install Flask:

``` bash
python3 -m pip install flask
```

If the system Python environment prevents global pip installation, use a
virtual environment:

``` bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install flask
```

### macOS dashboard environment

From the dashboard project directory:

``` bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install streamlit pandas streamlit-autorefresh requests
```

The dashboard may use `requests` to retrieve JSON from Flask. Install it
if `dashboard.py` imports it.

### Kali Linux VM

The attacker simulator uses Python's standard library. Check Python:

``` bash
python3 --version
```

Netcat is useful for manual testing:

``` bash
nc -vz 192.168.56.20 2222
nc -vz 192.168.56.20 8080
```

## 9. Project Structure

The main Ubuntu project directory is:

``` text
HoneyPot/
├── server.py
├── fake_shell.py
├── database.py
├── init_db.py
├── detector.py
├── api.py
├── dashboard.py
├── honeypot.db
└── attacker_simulator.py       # Run this on Kali Linux
```

Depending on how the files were organised, the dashboard and simulator
may be stored in separate directories or machines.

  -----------------------------------------------------------------------
  File                                Responsibility
  ----------------------------------- -----------------------------------
  `server.py`                         Starts the SSH-like and HTTP-like
                                      services, handles connections, and
                                      forwards events to the database
                                      logger

  `fake_shell.py`                     Implements the fake command
                                      interpreter and in-memory
                                      filesystem

  `init_db.py`                        Creates the SQLite database, events
                                      table, and indexes

  `database.py`                       Provides database connection, event
                                      insertion, and retrieval functions

  `detector.py`                       Reads database events and detects
                                      repeated login attempts and
                                      possible port scanning

  `api.py`                            Exposes health and event-retrieval
                                      endpoints through Flask

  `dashboard.py`                      Displays event and alert
                                      information using Streamlit

  `attacker_simulator.py`             Generates controlled SSH-like and
                                      HTTP test activity from Kali
  -----------------------------------------------------------------------

## 10. SQLite Database

The database file is `honeypot.db`.

SQLite is lightweight and serverless. The Python application connects
directly to the database file.

### Database schema

The `events` table contains:

  -----------------------------------------------------------------------
  Column                  Type                    Description
  ----------------------- ----------------------- -----------------------
  `id`                    INTEGER                 Auto-incrementing event
                                                  ID

  `timestamp`             TEXT                    UTC timestamp in ISO
                                                  8601 format

  `source_ip`             TEXT                    Source IP address

  `source_port`           INTEGER                 Source TCP port

  `destination_port`      INTEGER                 Honeypot destination
                                                  port

  `service`               TEXT                    Service name, such as
                                                  SSH or HTTP

  `username`              TEXT                    Username supplied
                                                  during login, where
                                                  applicable

  `event`                 TEXT                    Event type

  `details`               TEXT                    Command, HTTP request,
                                                  or additional event
                                                  information
  -----------------------------------------------------------------------

Indexes are created on `source_ip`, `timestamp`, and `event`.

### Initialise the database

Run from the Ubuntu project directory:

``` bash
python3 init_db.py
```

Expected message:

``` text
SQLite database initialized successfully!
```

The script uses `CREATE TABLE IF NOT EXISTS`, so it does not recreate an
existing table or erase its records.

### Inspect the database

``` bash
sqlite3 honeypot.db
```

Inside the SQLite prompt:

``` sql
.tables
.schema events

.headers on
.mode column

SELECT * FROM events ORDER BY id DESC LIMIT 20;
```

Count all events:

``` sql
SELECT COUNT(*) FROM events;
```

Summarise events by type:

``` sql
SELECT event, COUNT(*) AS total
FROM events
GROUP BY event
ORDER BY total DESC;
```

Summarise activity by source:

``` sql
SELECT source_ip, COUNT(*) AS total
FROM events
GROUP BY source_ip
ORDER BY total DESC;
```

Clear event records while preserving the table and schema:

``` sql
DELETE FROM events;
```

Exit SQLite:

``` sql
.quit
```

Deleting rows does not remove the database schema or stop future
logging.

## 11. Run the Honeypot

Start the services on Ubuntu from the project directory:

``` bash
python3 server.py
```

  Service             Protocol       Port
  ------------------- ---------- --------
  SSH-like service    TCP          `2222`
  HTTP-like service   TCP          `8080`

### Test the SSH-like service manually

From Kali:

``` bash
nc 192.168.56.20 2222
```

Enter dummy credentials and try supported fake-shell commands:

``` text
whoami
pwd
ls
cat passwords.txt
cd /etc
cat hostname
uname -a
exit
```

The fake shell responds using simulated data structures. It does not
execute commands on Ubuntu.

### Test the HTTP-like service

From Kali:

``` bash
curl http://192.168.56.20:8080/
```

Or use Netcat:

``` bash
nc 192.168.56.20 8080
```

Enter a simple HTTP request:

``` http
GET / HTTP/1.1
Host: 192.168.56.20
```

The HTTP handler records the request in SQLite.

## 12. Run the Attacker Simulator

The simulator runs on Kali and targets Ubuntu.

Its target configuration uses:

``` python
TARGET = "192.168.56.20"
SOURCE_IPS = [
    "192.168.56.11",
    "192.168.56.12",
    "192.168.56.13"
]
```

The simulator binds outgoing sockets to the selected source IP before
connecting. This creates activity associated with multiple source
addresses on the same Kali VM.

Run:

``` bash
python3 attacker_simulator.py
```

The simulator includes controlled profiles such as:

-   System reconnaissance.
-   Credential and file discovery.
-   Filesystem exploration.
-   HTTP path requests.

Example commands include `whoami`, `pwd`, `uname -a`, `hostname`, `ps`,
`ip addr`, `ls`, `cat passwords.txt`, `cat /etc/passwd`,
`cat /etc/shadow`, `find /`, and `sudo su`.

The fake shell may return simulated responses. The simulator does not
represent independent physical attackers.

## 13. Detection Engine

Run the detection engine on Ubuntu:

``` bash
python3 detector.py
```

The current SQLite-based detector reads the `events` table and applies
two time-window heuristics.

### Repeated login attempts

-   Threshold: 3 login attempts.
-   Time window: 5 minutes.
-   Event considered: `LOGIN_ATTEMPT`.
-   Events are grouped by source IP.

If an IP reaches the threshold within the window, the detector reports
possible brute-force activity.

### Possible port scanning

-   Threshold: 2 distinct destination ports.
-   Time window: 60 seconds.
-   Event considered: `CONNECTION`.
-   Events are grouped by source IP.

If an IP connects to at least two distinct destination ports within the
window, the detector reports possible port scanning.

These are heuristic indicators, not definitive proof of malicious
activity. A client that simply tests both available services may trigger
the port-scan rule.

The broader dashboard/reporting implementation may also include
command-pattern categories such as credential discovery, system
reconnaissance, user enumeration, filesystem discovery, and
privilege-escalation interest. These are indicators derived from command
strings, not proof that an attack succeeded. The standalone
`detector.py` described above implements the repeated-login and
port-scan checks.

## 14. Flask API

The Flask API runs on Ubuntu and retrieves event records from SQLite.

Start it:

``` bash
python3 api.py
```

It listens on:

``` text
http://0.0.0.0:5000
```

macOS accesses it using Ubuntu's host-only address:

``` text
http://192.168.57.2:5000
```

### API endpoints

  -----------------------------------------------------------------------
  Endpoint                Method                  Purpose
  ----------------------- ----------------------- -----------------------
  `/health`               GET                     Checks whether the API
                                                  is running

  `/events`               GET                     Returns the total event
                                                  count and up to the
                                                  latest 500 events
  -----------------------------------------------------------------------

Test from macOS:

``` bash
curl http://192.168.57.2:5000/health
curl http://192.168.57.2:5000/events
```

Expected health response:

``` json
{
  "status": "API running"
}
```

The events endpoint returns a JSON object with `total_events` and
`events`. Each event contains the database fields. The API returns the
latest 500 rows in chronological order for dashboard visualisation;
`total_events` counts all rows.

## 15. Streamlit Dashboard on macOS

The dashboard runs on macOS to keep visualisation separate from the
Ubuntu honeypot VM. It retrieves data through Flask and does not need
direct access to the SQLite database file.

### Configure the API URL

In `dashboard.py`:

``` python
API_URL = "http://192.168.57.2:5000/events"
```

Use the actual host-only address if it differs.

### Install dependencies

``` bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install streamlit pandas streamlit-autorefresh requests
```

### Start the dashboard

``` bash
streamlit run dashboard.py
```

Streamlit normally opens:

``` text
http://localhost:8501
```

### Automatic refresh

The dashboard uses `streamlit-autorefresh` to refresh periodically. A
typical configuration is:

``` python
from streamlit_autorefresh import st_autorefresh

st_autorefresh(interval=3000, key="honeypot_refresh")
```

The interval is 3,000 milliseconds (3 seconds). If Streamlit caching is
used, its cache TTL should be short enough to avoid stale API responses.

Dashboard capabilities in the developed version include event counts,
source analysis, an activity timeline, command exploration, security
alerts, and raw event inspection.

### Data flow

``` text
Honeypot Services
       |
       v
SQLite (Ubuntu)
       |
       v
Flask API (Ubuntu:5000)
       |
       v
Streamlit Dashboard (macOS:8501)
```

## 16. Wireshark Traffic Analysis

Wireshark is installed on Kali Linux and can inspect traffic between
Kali and Ubuntu.

Select the interface carrying `honeynet` traffic, usually `eth0`.

Useful display filters:

ICMP:

``` text
icmp
```

SSH-like service:

``` text
tcp.port == 2222
```

HTTP-like service:

``` text
tcp.port == 8080
```

Traffic involving Ubuntu:

``` text
ip.addr == 192.168.56.20
```

TCP SYN packets:

``` text
tcp.flags.syn == 1
```

Inspect packet layers such as Frame, Ethernet II, IPv4, TCP, and
application payload where visible.

TCP connection establishment uses the three-way handshake:

1.  SYN: client requests a connection.
2.  SYN-ACK: server acknowledges and responds.
3.  ACK: client acknowledges the server.

The project uses custom TCP interactions. The SSH-like service is **not
a real SSH protocol implementation**, so its application data is not
protected by SSH encryption. Do not use real credentials with it.

Wireshark is a packet analyser; it does not create the honeypot or
perform application-level event logging.

## 17. Demonstration Workflow

### Preparation

1.  Start the Ubuntu VM.
2.  Verify the internal and host-only IP addresses.
3.  Start `server.py` on Ubuntu.
4.  Start `api.py` on Ubuntu.
5.  Start the Streamlit dashboard on macOS.
6.  Verify that the dashboard can retrieve events from the API.

### Attack simulation

1.  Start Kali Linux.
2.  Verify connectivity to `192.168.56.20`.
3.  Run `attacker_simulator.py`.
4.  Observe the honeypot server terminal.
5.  Observe the dashboard refreshing with new activity.

### Database verification

On Ubuntu:

``` bash
sqlite3 honeypot.db
```

Then:

``` sql
.headers on
.mode column

SELECT id, timestamp, source_ip, destination_port,
       service, event, username, details
FROM events
ORDER BY id DESC
LIMIT 20;
```

This verifies that simulated activity is persisted in SQLite.

### Detection verification

Exit SQLite with `.quit`, then run:

``` bash
python3 detector.py
```

Explain the time-window rules and their limitations.

### Packet inspection

On Kali, open Wireshark, select the honeynet interface, and apply:

``` text
tcp.port == 2222 || tcp.port == 8080
```

Show the TCP connection and application traffic generated during the
simulation.

## 18. Troubleshooting

### Kali cannot ping Ubuntu

-   Kali and Ubuntu must use the same Internal Network name: `honeynet`.
-   Verify that the adapters are enabled.
-   Check addresses with `ip addr`.
-   Confirm both internal addresses use the same subnet.

### macOS cannot reach the Flask API

Check that:

1.  Ubuntu's host-only interface has `192.168.57.2/24`.
2.  macOS can ping `192.168.57.2`.
3.  Flask is running on Ubuntu.
4.  Flask is bound to `0.0.0.0`, not only `127.0.0.1`.
5.  The dashboard uses the correct API URL.

From macOS:

``` bash
ping 192.168.57.2
curl http://192.168.57.2:5000/health
curl http://192.168.57.2:5000/events
```

### Netcat reports connection refused

This usually means the destination is reachable but no service is
accepting connections on that port, or the connection is actively
rejected. Check that `server.py` is running and listening on the
expected port.

### No events appear in SQLite

Check that:

-   `server.py` is running.
-   The client connects to the correct Ubuntu IP and port.
-   `database.py` and `honeypot.db` are in the expected project
    directory.
-   The server process is using the same database file that you are
    inspecting.
-   No database error is printed in the server terminal.

The database path in `database.py` is relative (`honeypot.db`). Run the
application from the project directory consistently to avoid creating or
using another database file in a different working directory.

### Detector reports no brute-force activity

The detector only considers login attempts inside its five-minute window
and requires at least three attempts from the same source IP.

### Dashboard does not show new events

Test the API first:

``` bash
curl http://192.168.57.2:5000/events
```

If the API returns new events but the dashboard does not, check the API
URL, dashboard data-fetching code, cache TTL, and automatic-refresh
configuration.

### Inspect listening ports on Ubuntu

``` bash
sudo ss -lntp
```

Look for listeners on ports `2222`, `8080`, and `5000`.

## 19. Security Considerations and Limitations

This is an educational, low-interaction honeypot.

-   The SSH-like service is a custom TCP simulation, not a
    standards-compliant SSH server.
-   The fake shell supports only commands implemented in Python.
-   Commands are not executed by the Ubuntu host shell.
-   The fake filesystem is in memory and is not the real Ubuntu
    filesystem.
-   The HTTP service is a basic simulated handler, not a full production
    web server.
-   The simulator's multiple source IPs are aliases on one Kali VM, not
    independent attacker machines.
-   Detection rules are heuristic and can produce false positives.
-   The project is intended for an isolated lab, not direct exposure to
    the public internet.
-   Do not enter real passwords or sensitive information into the
    simulated login service.
-   Do not configure Bridged Adapter for the lab.
-   Do not expose the honeypot or API to untrusted networks without a
    separate security review.

The host-only API is intended for the local macOS dashboard. Additional
access controls and firewall restrictions would be required before using
a similar architecture in a less-trusted environment.

## 20. Future Enhancements

1.  **High-interaction honeypot:** Add a separate, isolated Linux
    environment with a genuine shell and filesystem for deeper attacker
    interaction.
2.  **Hybrid honeypot:** Retain the existing fake shell while routing
    selected sessions to a disposable, isolated Linux environment.
3.  **Improved detection:** Add configurable thresholds, rolling time
    windows, correlation rules, and severity scoring.
4.  **System-level monitoring:** Record process activity, file changes,
    and system calls inside a dedicated isolated environment.
5.  **Dashboard improvements:** Add filters by source IP, service, event
    type, and time range.
6.  **IP blocking:** Add carefully scoped firewall controls to restrict
    suspicious sources on the honeypot interface.
7.  **More realistic services:** Add additional decoy services and
    believable banners and responses.
8.  **Data export:** Support exporting selected events and reports for
    analysis.

------------------------------------------------------------------------

## Summary

The project demonstrates a local honeypot monitoring workflow:

-   A controlled attacker VM generates test activity.
-   An Ubuntu VM exposes simulated SSH-like and HTTP-like services.
-   A fake shell and filesystem provide a safe, controlled interaction
    layer.
-   SQLite stores connection, login, command, and HTTP events.
-   Python detection logic identifies selected suspicious patterns.
-   Flask exposes event data through an API.
-   A Streamlit dashboard on macOS visualises the activity.
-   Wireshark provides packet-level inspection of lab traffic.

The result is a modular educational platform for understanding network
deception, event collection, basic attack-behaviour detection, and
security monitoring.
