# 🛡️ Midnight SOC | Command Center 🛰️

<img src=".\midnight-logo.png" alt="alt text" width="460" height="350">

Midnight SOC, karmaşık ağ ve sunucu altyapıları için geliştirilmiş, gerçek zamanlı, platformlar arası (Windows/Linux) bir **Siber Güvenlik Operasyon Merkezi (SOC)** ve **Komuta Kontrol (C2)** platformudur.

Go'nun yüksek performansı ve React'ın modern arayüz kabiliyetlerini birleştiren Midnight, filonuzdaki tüm varlıkları tek bir cam arkasından (Single Pane of Glass) izlemenizi, yönetmenizi ve siber tehditlere karşı anında "Müdahale" etmenizi sağlar.

---

## 🚀 Ana Özellikler

* **🕵️‍♂️ Fleet Asset Management:** Tüm Windows ve Linux makinelerinizi anlık olarak izleyin.
* **⚔️ Interactive C2 Control:** Ajanlar üzerinde uzaktan `Deep Scan`, `Quarantine` (Ağ İzolasyonu) ve `Shutdown` komutlarını milisaniyeler içinde uygulayın.
* **📊 Real-time Forensic Stream:** WebSockets üzerinden akan anlık güvenlik loglarını, ağ trafiklerini ve süreç hareketlerini takip edin.
* **📡 Intelligence Engine:** DGA (Domain Generation Algorithm) tespiti ve yüksek entropili ağ sorguları için otomatik siber zekâ analizi.
* **🛡️ Active Hardening:** Linux (iptables) ve Windows (Netsh) firewall entegrasyonu ile tehlike anında otomatik varlık izolasyonu.
* **🔍 Vulnerability Scanner:** Sunuculardaki kritik zafiyetleri otomatik tarayan ve Dashboard'a raporlayan entegre motor.

---

## 🏗️ Teknik Mimari

### 🖥️ Frontend (Midnight-UI)

- **Framework:** React 18 + Vite
* **Styling:** Premium Glassmorphism Design System (Vanilla CSS)
* **Real-time:** WebSockets for instant telemetry
* **Design:** Dark Mode optimized, high-authority UI

### ⚙️ Backend (Midnight-Backend)

- **Language:** Go 1.26
* **Framework:** Fiber (High Performance)
* **Persistence:** Local JSON Audit Engine
* **Communication:** Bi-directional C2 polling & WebSocket broadcast

### 🛡️ Agent (Midnight-Go-Agent)

- **Language:** Go (Cross-Compile)
* **Compatibility:** Windows (EventLogs) & Linux (systemd service)
* **Execution:** Persistent background service with auto-restart

---

## 🛠️ Kurulum Rehberi

### 1. Backend & UI Hazırlığı (Windows)

```bash
# UI Derlemesi (Ayarlandıktan Sonra)
cd midnight-ui
npm install
npm run build

# Backend Başlatma
cd ../midnight-backend
go build -o midnight-backend.exe main.go
./midnight-backend.exe
```

### 2. Linux Agent Kurulumu (Service Mode)

Midnight Agent'ı Linux sunucunuzda kalıcı bir servis olarak çalıştırmak için:

```bash
# Binary'yi sunucuya aktarın ve yetki verin
chmod +x midnight-agent-linux
sudo mv ./midnight-agent-linux /usr/local/bin/midnight-agent

# Servis dosyasını oluşturun (IP'nizi güncellemeyi unutmayın)
export MIDNIGHT_SERVER=10.6.134.183
sudo systemctl enable midnight-agent
sudo systemctl start midnight-agent
```

---

## 🛡️ Etik Kullanım Notu

Bu yazılım eğitim ve siber savunma amaçlı geliştirilmiştir. Yalnızca yetkiniz dahilindeki sistemlerde kullanınız.

---
**Midnight SOC Master v8.5 [Ultimate C2 Edition]**
*Developed for elite cybersecurity operations.* 🫡🛡️⚔️🌐
