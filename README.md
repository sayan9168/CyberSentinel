# Advanced Cybersecurity Network Scanner

একটি **Advanced Cybersecurity Tool** যা নেটওয়ার্ক সিকিউরিটি অ্যাসেসমেন্টের জন্য তৈরি করা হয়েছে।

## 🚀 Features (বৈশিষ্ট্যসমূহ)

- ✅ **Port Scanning** - TCP পোর্ট স্ক্যানিং (1-65535)
- ✅ **Service Detection** - খোলা পোর্টে কোন সার্ভিস চলছে তা শনাক্তকরণ
- ✅ **Vulnerability Assessment** - পরিচিত CVE ভুলনারেবিলিটি চেক
- ✅ **Network Discovery** - হোস্টনেম ও IP রেজোলিউশন
- ✅ **Multi-threading** - দ্রুত স্ক্যানিংয়ের জন্য থ্রেডিং সাপোর্ট
- ✅ **Detailed Reporting** - JSON এবং টেক্সট রিপোর্ট জেনারেশন
- ✅ **Color-coded Output** - সহজে পড়ার জন্য রঙিন আউটপুট

## 📋 Requirements

- Python 3.6+
- কোনো এক্সটার্নাল লাইব্রেরি প্রয়োজন নেই (স্ট্যান্ডার্ড লাইব্রেরি ব্যবহার করা হয়েছে)

## 🔧 Installation

```bash
# কোনো ইন্সটলেশন প্রয়োজন নেই, সরাসরি রান করুন
python3 security_scanner.py --help
```

## 💡 Usage Examples

### বেসিক স্ক্যান
```bash
python3 security_scanner.py -t 192.168.1.1
```

### নির্দিষ্ট পোর্ট রেঞ্জ
```bash
python3 security_scanner.py -t 192.168.1.1 -p 1-1000
```

### নির্দিষ্ট পোর্ট
```bash
python3 security_scanner.py -t example.com -p 22,80,443
```

### ফুল স্ক্যান (সব পোর্ট)
```bash
python3 security_scanner.py -t 192.168.1.1 --full
```

### রিপোর্ট সেভ করা
```bash
python3 security_scanner.py -t 192.168.1.1 -o report.json
```

### কাস্টমাইজড থ্রেড ও টাইমআউট
```bash
python3 security_scanner.py -t 192.168.1.1 -T 200 --timeout 3
```

## 🎯 Command Line Options

| Option | Description |
|--------|-------------|
| `-t, --target` | টার্গেট IP বা হোস্টনেম (required) |
| `-p, --ports` | পোর্ট রেঞ্জ (default: 1-1024) |
| `--full` | ফুল পোর্ট স্ক্যান (1-65535) |
| `-T, --threads` | থ্রেড সংখ্যা (default: 100) |
| `--timeout` | সকেট টাইমআউট সেকেন্ডে (default: 2) |
| `-o, --output` | JSON রিপোর্ট আউটপুট ফাইল |
| `-v, --verbose` | ভার্বোজ আউটপুট |

## 🛡️ Vulnerability Detection

এই টুলটি নিচের পরিচিত ভুলনারেবিলিটিগুলো শনাক্ত করতে পারে:

- **CVE-2017-0144** - EternalBlue (SMB)
- **CVE-2020-0796** - SMBv3 Compression
- **CVE-2019-0708** - BlueKeep (RDP)
- **CVE-2021-44228** - Log4j
- **CVE-2015-3306** - ProFTPD mod_copy
- **CVE-2022-0543** - Redis Lua Sandbox Escape

## ⚠️ Disclaimer

**এই টুলটি শুধুমাত্র শিক্ষামূলক এবং অনুমোদিত সিকিউরিটি টেস্টিংয়ের জন্য ব্যবহার করুন।** 
অননুমোদিত সিস্টেমে স্ক্যান করা আইনত দণ্ডনীয় অপরাধ।

## 📝 Example Output

```
╔═══════════════════════════════════════════════════════════╗
║     ADVANCED CYBERSECURITY NETWORK SCANNER          ║
║           Security Assessment Tool v1.0                 ║
╚═══════════════════════════════════════════════════════════╝

[*] Resolving target: 192.168.1.1
[+] Resolved: 192.168.1.1 -> 192.168.1.1
[*] Starting scan on 192.168.1.1
[*] Port range: 1-1024
[*] Threads: 100
[*] Timeout: 2s

[*] Scanning ports 1-1024 on 192.168.1.1
[*] Performing vulnerability assessment...

================================================================================
ADVANCED CYBERSECURITY SCAN REPORT
================================================================================
Target: 192.168.1.1
Scan Time: 2024-01-15 10:30:45
Open Ports: 5

[+] OPEN PORTS
----------------------------------------
  Port 22    - SSH
  Port 80    - HTTP
  Port 443   - HTTPS
  Port 3306  - MySQL
  Port 8080  - HTTP-Proxy

[!] VULNERABILITIES DETECTED
----------------------------------------
  [CRITICAL] CVE-2017-0144
    Port: 445, Service: SMB
    Description: EternalBlue SMB vulnerability
    Recommendation: Apply MS17-010 patch immediately, disable SMBv1
================================================================================
```

## 👨‍💻 Author

Cybersecurity Tool - Educational Purpose

## 📄 License

MIT License - শিক্ষামূলক ব্যবহারের জন্য উন্মুক্ত
