# Fetch Zscaler ZIA ZPA Configuration using API

## 1. Introduction

This document provides step-by-step instructions to set up and run the standalone script that fetches Zscaler ZIA and ZPA configurations. The script exports configuration data from the Zscaler cloud (ZIA and ZPA) using REST APIs.

## 2. Script Overview

**Script Name:** `fetch_zscaler_zia_zpa_config.py`

The script fetches configuration data such as firewall rules, network objects, URL categories, and policies from Zscaler ZIA and ZPA, and stores them locally in the same directory where the script resides. It creates a new `config` folder, within which `zpa` and `zia` subfolders are created, and the files are stored inside these subfolders.

## 3. Prerequisites

**System Requirements:**
- Python 3.10 or higher
- Network connectivity to reach Zscaler cloud
- Valid Zscaler ZIA and ZPA administrator credentials

## 4. Python Environment Setup

### 4.1 Create Virtual Environment (Recommended)

**Linux / macOS:**
```bash
python3 -m venv venv
source venv/bin/activate
```

**Windows:**
```bash
python -m venv venv
venv\Scripts\activate
```

### 4.2 Install Dependencies

```bash
pip install -r requirements.txt
```

### 4.3 Verify Installation

```bash
python --version
pip list | grep requests
```

## 5. Zscaler Prerequisites

### For ZIA

- Cloud URL (e.g., https://admin.zscaler.net)
- Zscaler Admin Username
- Zscaler Admin Password
- Zscaler API Key

### For ZPA

- Cloud URL (e.g., https://config.private.zscaler.com)
- Customer ID
- Client ID
- Client Secret

> **Important:** Please ensure that the cloud URLs used are correct, otherwise even if the login credentials are correct, the login will not work.

## 6. Script Execution

**Command Syntax:**

```bash
python3 fetch_zscaler_zia_zpa_config.py
```

> **Note:**
> - ZIA API to export the policy config has a rate limit of 1 API call per hour. So, if the script execution is successful and you try to execute it again within an hour then in the next iteration, the API will not return the ZIA policy configs and hence the new zip will not include the ZIA policy config files.
> - There is no rate limit on ZPA policy and other objects fetch APIs.

## 7. Output

All configuration files will be generated based on API response and saved in the `zia` and `zpa` directories.

## 8. Best Practices

- Do not hardcode credentials
- Use admin credentials carefully
- Keep backup of downloaded configurations
