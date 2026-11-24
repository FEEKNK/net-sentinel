# NetSentinel — Cross-Platform Network Monitor & Hybrid IDS

> **SolarWinds + Snort Hybrid (NOC + SOC)** — ระบบสแกนวงเครือข่าย (IP/Subnet Scanner), ดักจับแพ็กเก็ตและตรวจจับภัยคุกคาม (Snort `.rules` + Behavioral IDS), ติดตามแบนด์วิดท์ (SNMP / Local NIC), และระบบป้องกันอัตโนมัติ (Active Response พร้อมโหมด Dry-Run) บน **Windows** และ **Linux**

---

## ความสามารถหลัก (Key Features)

1. **IP & Subnet Scanner** — ค้นหาเครื่องออนไลน์ในวง LAN (ARP / ICMP / TCP Connect), ดึง MAC Address, OUI Vendor, Hostname, Latency (ms) และพอร์ตที่เปิดอยู่
2. **Live Packet Sniffer & Hybrid IDS** — ดักจับแพ็กเก็ตด้วย `Scapy` (ใช้ Npcap บน Windows / libpcap บน Linux) พร้อมตัวตรวจจับพฤติกรรม (**Port Scan**, **SYN Flood**, **ARP Spoofing**) และตัวอ่านกฎ **Snort `.rules`** พื้นฐาน
3. **SNMPv2c & Local NIC Bandwidth Monitor** — ดึงค่า CPU/RAM และ Bandwidth จาก Router/Switch ผ่าน SNMPv2c หรือวัดทราฟฟิกของ Network Card เครื่องที่รันระบบโดยตรง
4. **Active Response / Auto-Block (Safe-by-Default)** — สั่งบล็อก IP ผ่าน `netsh advfirewall` (Windows) หรือ `iptables` (Linux) โดยตั้งค่าเริ่มต้นเป็น **Dry-Run Mode** พร้อม Whitelist ป้องกันการบล็อก Gateway หรือเครื่องตัวเอง
5. **Real-time NOC/SOC Dashboard** — หน้าเว็บ React + WebSocket แสดงผลแบบ Real-time พร้อม **Attack Simulator** สำหรับจำลองเหตุการณ์โจมตีเพื่อศึกษาและทดสอบระบบอย่างปลอดภัย

---

## ข้อกำหนดระบบ (Prerequisites)

- **Python 3.12+** และ [`uv`](https://docs.astral.sh/uv/)
- **Node.js 20+** และ `npm`
- **Windows:** ติดตั้ง [Npcap](https://npcap.com/) (แนะนำเปิด *WinPcap API-compatible Mode*) และรัน Terminal ด้วยสิทธิ์ **Administrator** หากต้องการ Live Sniffing หรือ Enforce Firewall จริง
- **Linux:** ติดตั้ง `libpcap-dev` และ `iptables` และรัน Backend ด้วย `sudo` หากต้องการ Live Sniffing หรือ Enforce Firewall จริง

*(หากรันแบบ User ปกติ ระบบยังสามารถใช้งาน Subnet TCP/Ping Scan, Local NIC Monitor, Snort Rules Editor และ Attack Simulator เพื่อการเรียนรู้ได้เต็มรูปแบบ)*

---

## การติดตั้งและเริ่มต้นใช้งาน (Quick Start)

### 1. Backend (FastAPI + Python)

```bash
cd backend
uv sync
uv run uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

### 2. Frontend (React + Vite)

```bash
cd frontend
npm install
npm run dev
```

เปิดเบราว์เซอร์ไปที่ `http://localhost:5173`

---

## การรันทดสอบ (Tests)

```bash
cd backend
uv run pytest -v

cd ../frontend
npm run build
```
