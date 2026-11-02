# 🌐 Mihomo Pools — Automated Country-Split Proxy Subscriptions

Pipeline otomatis pengujian dan pengelompokan node proxy publik (VLESS & Trojan) berdasarkan negara egress, diperbarui setiap 6 jam via GitHub Actions.

Dirancang untuk digunakan langsung sebagai **Mihomo / Clash Meta Proxy Providers** maupun universal client subscription (Xray / V2Ray).

---

## 🚀 Endpoint Subscriptions

Ganti `<CC>` dengan kode negara 2 huruf (misal: `SG`, `ID`, `US`, `JP`, `DE`, `GB`) atau gunakan `ALL`.

### 1. Mihomo Native Proxy-Provider (YAML)
Format native list `proxies:` yang siap di-include dalam konfigurasi Mihomo / Clash Meta:
- **Raw URL:**
  `https://raw.githubusercontent.com/latifangren/mihomo-pools/gh-pages/providers/<CC>.yaml`
  Contoh:
  - All: `https://raw.githubusercontent.com/latifangren/mihomo-pools/gh-pages/providers/ALL.yaml`
  - SG: `https://raw.githubusercontent.com/latifangren/mihomo-pools/gh-pages/providers/SG.yaml`
  - ID: `https://raw.githubusercontent.com/latifangren/mihomo-pools/gh-pages/providers/ID.yaml`
  - US: `https://raw.githubusercontent.com/latifangren/mihomo-pools/gh-pages/providers/US.yaml`
  - JP: `https://raw.githubusercontent.com/latifangren/mihomo-pools/gh-pages/providers/JP.yaml`

### 2. Universal Base64 Subscription
Format standar aplikasi V2Ray/Xray/v2rayN:
- **Raw URL:**
  `https://raw.githubusercontent.com/latifangren/mihomo-pools/gh-pages/subs/<CC>.txt`

### 3. Plain URI List
Format satu link URI per baris:
- **Raw URL:**
  `https://raw.githubusercontent.com/latifangren/mihomo-pools/gh-pages/plain/<CC>.txt`

---

## 🛠️ Cara Pakai di Config Mihomo

Tambahkan block `proxy-providers` dan `proxy-groups` pada `config.yaml` Mihomo Anda:

```yaml
proxy-providers:
  provider-sg:
    type: http
    url: "https://raw.githubusercontent.com/latifangren/mihomo-pools/gh-pages/providers/SG.yaml"
    interval: 3600
    path: ./providers/sg.yaml
    health-check:
      enable: true
      interval: 300
      url: https://www.gstatic.com/generate_204

  provider-all:
    type: http
    url: "https://raw.githubusercontent.com/latifangren/mihomo-pools/gh-pages/providers/ALL.yaml"
    interval: 3600
    path: ./providers/all.yaml
    health-check:
      enable: true
      interval: 300
      url: https://www.gstatic.com/generate_204

proxy-groups:
  - name: "AUTO-SG"
    type: url-test
    use:
      - provider-sg
    url: https://www.gstatic.com/generate_204
    interval: 180

  - name: "MANUAL-SELECT"
    type: select
    use:
      - provider-all
```

---

## ⚙️ Menjalankan Builder Secara Manual

Anda dapat menjalankan validator dan generator di mesin lokal:

```bash
# Uji dan build dari snapshot lokal:
python3 builder.py --input configs.txt --outdir dist

# Fetch online langsung dari berbagai sumber publik terpercaya:
python3 builder.py --fetch --outdir dist --concurrency 35 --timeout 3.5
```
