# WebSec-Auditor

[![Python](https://img.shields.io/badge/python-3.9%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](#license)

WebSec-Auditor là công cụ tự động audit bảo mật web bằng Python. Công cụ crawl website, khám phá endpoint/form và chạy các scanner mỏng (lightweight) tập trung vào OWASP Top 10 cùng các cấu hình sai phổ biến.

> **Cảnh báo pháp lý — hãy đọc trước khi sử dụng**
> Chỉ sử dụng công cụ này trên hệ thống bạn **sở hữu** hoặc đã có **ủy quyền bằng văn bản** để kiểm thử. Việc quét máy chủ không thuộc quyền của bạn có thể vi phạm pháp luật và điều khoản dịch vụ. Bạn chịu trách nhiệm tuân thủ pháp luật tại quốc gia của mình.
>
> *Only use this tool on systems you own or have explicit written permission to test. Unauthorised scanning may be illegal.*

## Tính năng

| Module | Chức năng |
| --- | --- |
| **Crawler** (`utils/crawler.py`) | BFS theo độ sâu (`max_depth`), trích xuất `<a href>` và `<form>` + tham số GET/POST, trả về danh sách `Endpoint` |
| **HeaderScanner** (`scanners/headers.py`) | Kiểm tra `Content-Security-Policy`, `X-Frame-Options`, `Strict-Transport-Security`, `X-Content-Type-Options` |
| **SQLiScanner** (`scanners/sqli.py`) | Error-based + difference-based: so sánh response với baseline sau khi inject `'`, `"`, `1' OR '1'='1` |
| **XSSScanner** (`scanners/xss.py`) | Gửi `<script>alert(1)</script>` và biến thể, kiểm tra payload có bị phản chiếu nguyên vẹn không |
| **SSLScanner** (`scanners/ssl_scan.py`) | Kiểm tra phiên bản TLS, ngày hết hạn chứng chỉ, cipher suite yếu bằng `ssl`/`socket` |
| **DirectoryScanner** (`scanners/directory.py`) | Thử truy cập `/admin`, `/backup.zip`, `/.git/config`, `/robots.txt`, `/.env`… theo status 200/403 |
| **Engine** (`engine.py`) | Điều phối crawl + scan song song (`concurrent.futures`), tổng hợp `ScanResult` |
| **Report** (`report/`) | Xuất JSON có cấu trúc và HTML nhóm theo severity (High/Medium/Low/Info) |
| **CLI** (`cli.py`) | `argparse`, in tiến trình, hỗ trợ `full`/`quick`/từng scanner |

## Cấu trúc thư mục

```
WebSec-Auditor/
├── cli.py              # Giao diện dòng lệnh
├── engine.py           # Điều phối crawler + scanners
├── models.py           # Endpoint, Finding, ScanResult, BaseScanner
├── utils/
│   └── crawler.py      # Crawler BFS
├── scanners/
│   ├── headers.py
│   ├── sqli.py
│   ├── xss.py
│   ├── ssl_scan.py
│   └── directory.py
├── report/
│   ├── json_report.py
│   └── html_report.py
├── tests/
│   ├── test_headers.py
│   ├── test_sqli.py
│   ├── test_xss.py
│   └── test_engine.py
├── requirements.txt
└── README.md
```

## Cài đặt

Yêu cầu Python >= 3.9.

```bash
git clone https://github.com/trannguyenxuan27-ux/WebSec-Auditor.git
cd WebSec-Auditor
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Cách sử dụng

### Quét đầy đủ (mặc định)

```bash
python cli.py --url https://example.com --output json --output-file report.json
```

### Quét nhanh (chỉ headers / ssl / dir — ít xâm nhập nhất)

```bash
python cli.py --url https://example.com --scan-type quick --output html
```

### Quét một scanner cụ thể

```bash
python cli.py --url https://example.com --scan-type sqli
python cli.py --url https://example.com --scan-type xss --threads 10 --timeout 15
```

### Tùy chỉnh crawl / hiệu năng

```bash
python cli.py --url https://example.com \
  --max-depth 3 \
  --max-urls 200 \
  --threads 5 \
  --timeout 10 \
  --delay 0.5
```

| Tham số | Mô tả | Mặc định |
| --- | --- | --- |
| `--url` | URL mục tiêu (bắt buộc) | — |
| `--scan-type` | `full`, `quick`, `headers`, `sqli`, `xss`, `ssl`, `dir` | `full` |
| `--output` | `json` hoặc `html` | `json` |
| `--output-file` | Đường dẫn file kết quả | `report.json` / `report.html` |
| `--max-depth` | Độ sâu crawl | `2` |
| `--timeout` | Timeout mỗi request (giây) | `10` |
| `--threads` | Số luồng song song | `5` |
| `--delay` | Delay giữa các request (rate limiting) | `0.5` |

### Định dạng đầu ra

**JSON** — metadata (target, thời gian, summary) + danh sách finding với `endpoint`, `scanner`, `severity`, `evidence`, `recommendation`.

**HTML** — báo cáo trực quan, nhóm theo High → Medium → Low → Info.

Ví dụ một finding:

```json
{
  "endpoint": "http://example.com/search?q=x",
  "scanner": "xss",
  "severity": "High",
  "title": "Reflected XSS in 'q'",
  "evidence": "Payload '<script>alert(1)</script>' was reflected verbatim",
  "recommendation": "Contextually encode output and add CSP."
}
```

## Kiểm thử

```bash
python -m unittest discover -s tests -v
```

Các test sử dụng mock HTTP nên không cần mạng và không chạm vào máy chủ thật.

## Ghi chú kỹ thuật

- Mọi request được bọc `try/except`; lỗi được ghi log và quét tiếp — chương trình không crash vì một endpoint lỗi.
- `delay` giữa các request giúp tránh làm quá tải server mục tiêu.
- Các scanner phát hiện theo heuristic (error/difference/reflection). Kết quả là **nghi vấn cần xác minh thủ công**, không phải bằng chứng khẳng định. Hãy xác nhận thêm bằng công cụ chuyên sâu (Burp Suite, sqlmap…) chỉ trên mục tiêu đã ủy quyền.

## License

Released under the [MIT License](https://opensource.org/licenses/MIT).
