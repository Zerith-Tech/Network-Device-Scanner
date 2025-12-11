---

# Network Device Scanner

A lightweight Python-based tool that maps devices on a local network by performing an **ARP scan** and identifying devices by their **MAC address vendor (OUI)**.
Designed for learning, experimenting with Scapy, and building foundations for more advanced network reconnaissance tooling.

---

## 🚀 Features

* 🔍 **ARP Network Scanning** — discovers active devices on a given subnet
* 🏷️ **MAC Vendor Identification** (local OUI DB + optional online lookups)
* ⚠️ **Flagging Unknown Devices** — helps spot unrecognized hardware
* 🖥️ **Auto-detect Local Subnet** (optional)
* ⏱️ Displays scan duration + number of hosts found
* 🧩 Clean, structured code built for extensibility

---

## 🛠️ Planned Enhancements

These features are coming soon:

* **`--json` output**
  Export scan results in structured JSON for scripting, automation, or importing into other tools.

* **`--only-unknown` filter**
  Show *only* devices with an unknown vendor — helpful for spotting anomalies quickly.

---

## 📦 Requirements

* Python 3.8+
* Scapy
* Requests
* Root privileges (ARP requires raw sockets)

Install dependencies:

```bash
pip install scapy requests
```

---

## ⚙️ How It Works

1. The scanner sends ARP requests to each IP in the target subnet.

2. Active devices reply with their IP + MAC address.

3. The tool:

   * normalizes the MAC,
   * extracts the OUI (first 3 bytes),
   * looks up the manufacturer in a small offline OUI database,
   * optionally queries an online MAC vendor API,
   * flags any device with no known vendor match.

4. Results are printed in a clean, tabular format with flags like:

   * `UNKNOWN_VENDOR`
   * `THIS_HOST`

---

## 📚 Usage

### Basic scan (auto-detect network)

```bash
sudo python3 network.py
```

### Scan a specific network (CIDR notation)

```bash
sudo python3 network.py -t 192.168.1.0/24
```

### Use online vendor lookup (slower)

```bash
sudo python3 network.py -t 192.168.1.0/24 --online
```

### Specify a network interface

```bash
sudo python3 network.py -t 192.168.1.0/24 -i wlan0
```

### Adjust timeout (default: 15 seconds)

```bash
sudo python3 network.py -t 192.168.1.0/24 --timeout 3
```

---

## 📑 Example Output

```ruby
[+] Scanning network 192.168.1.0/24 via ARP...

Discovered devices:

IP Address       MAC Address        Vendor                              Flags
-----------------------------------------------------------------------------
192.168.1.1      3C:5A:37:AA:BB:CC  Google, Inc.                        
192.168.1.42     F4:F5:E8:DE:AD:BE  Apple, Inc.                         THIS_HOST
192.168.1.73     80:FA:5B:00:11:22  Unknown                             UNKNOWN_VENDOR

[+] Scan completed in 2.31 seconds. Found 3 device(s).
```

---

## 🔐 Notes & Limitations

* ARP only discovers devices on the **same Layer-2 network** (local subnet).
* Some virtualized or locally-administered MAC addresses may not resolve to a known vendor.
* Online vendor lookups may be rate-limited or unavailable depending on the API.
* For home networks, `/24` subnets are typical and auto-detection usually works well.

---

## 🧠 Why This Project Exists

This tool was built as part of a personal learning journey into:

* network enumeration
* packet crafting with Scapy
* vendor identification
* building real-world hacking tooling from scratch

It’s designed for clarity, not complexity — something you can read, understand, and extend easily.

---

## 🤝 Contributing

Suggestions, improvements, and PRs are welcome — especially for extending the OUI database, improving output formatting, or helping implement planned features like JSON export.

---

## 📜 License

MIT License — use, modify, and distribute freely.

---
