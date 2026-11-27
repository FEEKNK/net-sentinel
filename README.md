# NetSentinel — Cross-Platform Network Monitor & Hybrid IDS

> **SolarWinds + Fing + Nmap + Snort + Mini Wireshark** — ระบบสแกนวงเครือข่าย ตรวจจับภัยคุกคาม วิเคราะห์แพ็กเก็ต เฝ้าดูสุขภาพระบบ และป้องกันอัตโนมัติ (Active Response พร้อมโหมด Dry-Run) บน **Windows** และ **Linux**

---

## ความสามารถหลัก (Key Features)

1. **Easy Mode & Pro SOC Mode:** สลับระหว่างหน้าจอ 3 แท็บสำหรับผู้ใช้ทั่วไป (พร้อมปุ่ม **1-Click Health Check**) และหน้าจอ 8 แท็บสายเจาะลึก
2. **IP / Subnet & Port Scanner:** สแกนวง LAN (ARP / ICMP / SSDP / mDNS / NetBIOS), OS Fingerprinting, Banner Grabbing, Custom Port Range / UDP Scan, Risk Score (เกรด A–F), และตรวจจับเครื่องแปลกหน้า (**Rogue Device Alert**)
3. **Interactive Topology Map & Wake-on-LAN:** แผนผังเครือข่ายแบบคลิกดูประวัติ Latency / Uptime พร้อมปุ่มปลุกเครื่องระยะไกล
4. **Live Packet Sniffer & Hybrid IDS:** ดักจับทราฟฟิก (`Scapy`), ตัวตรวจจับพฤติกรรม (**Port Scan, SYN Flood, ARP Spoof**), กฎ **Snort `.rules`** พร้อม **PCRE Regex** และ **TCP Stream Reassembly**
5. **Traffic Forensics & PCAP Lab:** Packet Inspector (Hex/ASCII + Follow TCP Stream), Display Filter, Export & Upload `.pcap` (Wireshark-compatible), Top Talkers, DNS Query Monitor, Syslog Server (`UDP 5140`), และ Export Audit Report (CSV / PDF)
6. **Tools & Monitors:** Process-to-Network Socket Viewer, Wi-Fi Signal & Channel Analyzer, Traceroute & Speed Test, HTTP/SSL Certificate Expiration Monitor, และ Internet Watchdog
7. **Active Response & Alerting:** สั่งบล็อกผ่าน `netsh advfirewall` (Windows) / `iptables` (Linux) โดยตั้งค่าเริ่มต้นเป็น **Dry-Run Mode**, Whitelist ป้องกัน Gateway/Host, Passcode Lock, และแจ้งเตือนผ่าน Discord / Telegram / Threat Intel (AbuseIPDB)

---

## การติดตั้งและเริ่มต้นใช้งาน (Quick Start)

### วิธีที่ 1: รันพัฒนาด้วยคำสั่งเดียว (Dev Mode)

```bash
# 1. ติดตั้ง Dependencies (ครั้งแรกเท่านั้น)
cd backend && uv sync
cd ../frontend && npm install
cd .. && npm install

# 2. รันทั้ง Backend + Frontend พร้อมกัน
npm run dev
```

เปิดเบราว์เซอร์ไปที่ `http://localhost:5173`

### วิธีที่ 2: รันพอร์ตเดียว (Single-Port Production Mode)

```bash
cd frontend && npm run build
cd ../backend && uv run uvicorn app.main:app --host 127.0.0.1 --port 8000
```

เปิดเบราว์เซอร์ไปที่ `http://127.0.0.1:8000`

### วิธีที่ 3: รันผ่าน Docker (Linux)

```bash
docker build -t net-sentinel .
docker run --rm --net=host --cap-add=NET_RAW --cap-add=NET_ADMIN net-sentinel
```

---

## การรันทดสอบ (Tests)

```bash
cd backend && uv run pytest -v
cd ../frontend && npm run build
```

---

## ข้อกำหนดการใช้งานอย่างรับผิดชอบ (Responsible Use)

ซอฟต์แวร์นี้พัฒนาขึ้นเพื่อ **การเฝ้าระวัง ป้องกัน และศึกษาเครือข่ายของตนเองหรือเครือข่ายที่ได้รับอนุญาตเท่านั้น** (Blue Team / Defensive Security) ห้ามนำไปใช้สแกนหรือรบกวนระบบของผู้อื่นโดยไม่ได้รับอนุญาต เผยแพร่ภายใต้สัญญาอนุญาต [MIT License](LICENSE)
