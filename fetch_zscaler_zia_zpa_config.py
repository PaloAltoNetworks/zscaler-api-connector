import argparse, urllib3, requests, json, sys
import time, hashlib, os, traceback, pwinput
import zipfile, io, shutil
from datetime import datetime, timedelta
from typing import List, Tuple, Optional
import logging

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

'''
IP Source Groups            https://help.zscaler.com/zia/firewall-policies#/ipSourceGroups-get
IPv6 Source Groups          https://help.zscaler.com/zia/firewall-policies#/ipSourceGroups/ipv6SourceGroups-get 
IP Destination Groups       https://help.zscaler.com/zia/firewall-policies#/ipDestinationGroups-get 
IPv6 Destination Groups     https://help.zscaler.com/zia/firewall-policies#/ipDestinationGroups/ipv6DestinationGroups-get 
Network applications        https://help.zscaler.com/zia/firewall-policies#/networkApplications-get 
Network application groups  https://help.zscaler.com/zia/firewall-policies#/networkApplicationGroups-get 
Network Services            https://help.zscaler.com/zia/firewall-policies#/networkServices-get 
Network Service Groups      https://help.zscaler.com/zia/firewall-policies#/networkServiceGroups-get 
URL Categories              https://help.zscaler.com/zia/url-categories#/urlCategories-get 
File Blocking               https://help.zscaler.com/zia/file-type-control-policy#/customFileTypes-get 
Locations                   https://help.zscaler.com/zia/location-management#/locations-get 
Location Groups             https://help.zscaler.com/zia/location-management#/locations/groups-get 
Device Groups               https://help.zscaler.com/zia/device-groups#/deviceGroups-get 
Departments                 https://help.zscaler.com/zia/user-management#/departments-get 
Groups                      https://help.zscaler.com/zia/user-management#/groups-get 
Policies                    https://help.zscaler.com/zia/policy-export#/exportPolicies-post
'''

ZIA_CLOUD_URL   = None
ZIA_USERNAME    = None
ZIA_PASSWORD    = None
ZIA_API_KEY     = None
ZPA_USERNAME    = None
ZPA_PASSWORD    = None
ZPA_CUSTOMER_ID = None
ZPA_CLOUD_URL   = None
logger          = None

INDIVIDUAL_JSONS = True
JSONS_ZIP        = True
ZIA_API          = True
ZPA_API          = True

logger = logging.getLogger("mylogger")

def print_output(jsondata):
    print(json.dumps(jsondata,indent=4))

def setup_logger(log_file):
    logger.setLevel(logging.DEBUG)
    
    console_output=0
    
    formatter = logging.Formatter(f"%(asctime)s - %(levelname)s - message: %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
    
    file_handler = logging.FileHandler(log_file, mode="a", encoding="utf-8")
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    
    if console_output==1:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
    
    return logger

def export_policies(session: requests.Session,
                    base_url: str,
                    policy_types: List[str],
                    output_dir: str,
                    output_path: Optional[str] = None) -> Tuple[bytes, Optional[str]]:
    """
    Export one or more Zscaler policies via API and extract to output_dir.

    :param session: Authenticated requests.Session instance
    :param base_url: Base URL of the API, e.g. "https://<tenant>.zscloud.net"
    :param policy_types: List of policy types to export (e.g. ["FIREWALL", "URL_FILTERING"])
    :param output_dir: Directory where ZIP contents should be extracted
    :param output_path: Optional path to save the resulting ZIP file
    :return: Tuple (response_bytes, error_message). If error_message is None, it's success.
    """

    url = f"{base_url.rstrip('/')}/api/v1/exportPolicies"
    headers = {
        "Content-Type": "application/json"
    }

    payload = policy_types

    try:
        resp = session.post(url, headers=headers, json=payload)
    except requests.RequestException as e:
        return b"", f"Request failed: {str(e)}"

    if resp.status_code != 200:
        # Return the body text as error (maybe JSON)
        return b"", f"Error fetching policies: {resp.status_code} {resp.text}"

    content = resp.content
    
    if output_path:
        # ensure output_dir exists
        os.makedirs(output_dir, exist_ok=True)

        # Save the ZIP file
        # with open(output_path, "wb") as f:
        #     f.write(content)
        
        # Extract ZIP contents directly to output_dir without saving ZIP file
        try:
            with zipfile.ZipFile(io.BytesIO(content), 'r') as zip_ref:
                zip_ref.extractall(output_dir)
                
            print(f"ZIP_EXTRACTED_TO: {output_dir}")
            
        except zipfile.BadZipFile:
            return b"", "Error: Downloaded file is not a valid ZIP file"
        except Exception as e:
            return b"", f"Error extracting ZIP file: {str(e)}"

    return content, None

def validate_credentials(platform):
    """Validate that all required Zscaler (ZIA/ZPA) credentials are present and not empty."""
    missing_fields = []
    
    # ~ print("\nZIA_CLOUD_URL : ",ZIA_CLOUD_URL)
    # ~ print("ZIA_USERNAME : ",ZIA_USERNAME)
    # ~ print("ZIA_PASSWORD : ",ZIA_PASSWORD)
    # ~ print("ZIA_API_KEY : ",ZIA_API_KEY)
    # ~ print("ZPA_USERNAME : ",ZPA_USERNAME)
    # ~ print("ZPA_PASSWORD : ",ZPA_PASSWORD)
    # ~ print("ZPA_CUSTOMER_ID : ",ZPA_CUSTOMER_ID)
    # ~ print("ZPA_CLOUD_URL : ",ZPA_CLOUD_URL)
    
    if platform == "ZIA":
        if not ZIA_CLOUD_URL or not ZIA_CLOUD_URL.strip():
            missing_fields.append("CLOUD_URL")
        if not ZIA_USERNAME or not ZIA_USERNAME.strip():
            missing_fields.append("ZSCALER_USERNAME")
        if not ZIA_PASSWORD or not ZIA_PASSWORD.strip():
            missing_fields.append("ZSCALER_PASSWORD")
        if not ZIA_API_KEY or not ZIA_API_KEY.strip():
            missing_fields.append("ZSCALER_API_KEY")
    
    elif platform == "ZPA":
        if not ZPA_USERNAME or not ZPA_USERNAME.strip():
            missing_fields.append("ZPA_USERNAME")
        if not ZPA_PASSWORD or not ZPA_PASSWORD.strip():
            missing_fields.append("ZPA_PASSWORD")
        if not ZPA_CUSTOMER_ID or not ZPA_CUSTOMER_ID.strip():
            missing_fields.append("ZPA_CUSTOMER_ID")
        if not ZPA_CLOUD_URL or not ZPA_CLOUD_URL.strip():
            missing_fields.append("ZPA_CLOUD_URL")
    
    if missing_fields:
        print(f"ERROR_MISSING_CREDENTIALS: {', '.join(missing_fields)}")
        logger.error(f"ERROR_MISSING_CREDENTIALS: {', '.join(missing_fields)}")
        sys.exit(1)

# --- Obfuscate API key ---
def obfuscateApiKey():
    try:
        # Validate ZIA_API_KEY is not empty (can be 1 character to any length)
        if not ZIA_API_KEY or len(ZIA_API_KEY.strip()) == 0:
            print("ERROR_INVALID_API_KEY")
            logger.error("Invalid API")
            return None, None
            
        seed = ZIA_API_KEY
        now = int(time.time() * 1000)
        n = str(now)[-6:]
        r = str(int(n) >> 1).zfill(6)
        key = ""
        
        # Handle cases where ZIA_API_KEY might be shorter than expected indices
        for i in range(0, len(str(n)), 1):
            digit = int(str(n)[i])
            if digit < len(seed):
                key += seed[digit]
            else:
                # If digit is larger than seed length, wrap around
                key += seed[digit % len(seed)]
                
        for j in range(0, len(str(r)), 1):
            digit = int(str(r)[j]) + 2
            if digit < len(seed):
                key += seed[digit]
            else:
                # If digit is larger than seed length, wrap around
                key += seed[digit % len(seed)]

        return now, key
    
    except (ValueError, IndexError) as e:
        print("ERROR_OBFUSCATING_API_KEY")
        return None, None
    except Exception as e:
        print("ERROR_PROCESSING_API_KEY")
        return None, None

# -----------------------------
# SAVE JSON TO FILE
# -----------------------------
def save_json(data, output_dir, filename):
    with open(os.path.join(output_dir, filename), "w") as f:
        json.dump(data, f, indent=4)
    #print(f"Saved file: {filename}")

# -----------------------------
# AUTH: Get OAuth Token
# -----------------------------
def zpa_authenticate():
    url = f"{ZPA_CLOUD_URL}/signin"
    payload = {
        "client_id": ZPA_USERNAME,
        "client_secret": ZPA_PASSWORD
    }
    headers = {
        "Content-Type": "application/x-www-form-urlencoded"
    }
    
    try:
        resp = requests.post(url, headers=headers, data=payload, verify=False)
    except requests.RequestException as e:
        print("FAILED_TO_ESTABLISH_ZPA_CONNECTION")
        logger.error(f"Failed to establish ZPA connection")
        return None
    
    # Check HTTP status
    if resp.status_code != 200:
        # Try to parse JSON error body
        err_body = None
        try:
            err_body = resp.json()
        except ValueError:
            logger.error(f"ZPA Login Failed: HTTP {resp.status_code} — {resp.text}")
            print("ZPA_LOGIN_FAILED")
            return None

        # err_body is JSON
        err_id = err_body.get("id") or err_body.get("error")
        err_reason = err_body.get("reason") or err_body.get("error_description")
        
        if err_id == "invalid_client":
            logger.error(f"ZPA Login Failed: {err_reason}")
            print("ZPA_LOGIN_FAILED")
        
        return None

    # On success
    try:
        data = resp.json()
    except ValueError:
        print("INVALID_AUTH_RESPONSE")
        return None
    
    token = data.get("access_token")
    if not token:
        print("NO_ACCESS_TOKEN_FOUND")
        return None
    
    print("ZPA_AUTHENTICATED_SUCCESSFULLY")
    logger.info(f"ZPA Authentication successfull")
    
    return token

# -----------------------------
# LOGOUT
# -----------------------------
def zpa_logout(token):
    url = f"{ZPA_CLOUD_URL}/signout"
    payload={}
    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {token}'
              }
    try:
        response = requests.request("POST", url, headers=headers, data=payload, verify=False)
        #print("response : ",response)
        if response.status_code == 200:
            print("ZPA_LOGGED_OUT_SUCCESSFULLY")
            logger.info("ZPA logged out successfully")
        else:
            print("ZPA_LOGGING_OUT_FAILED")
            logger.error("ZPA logging out failed")
    except:
        print("ZPA_LOGGING_OUT_FAILED")
        logger.error("ZPA logging out failed")

# -----------------------------
# GET ALL DATA USING API CALLS
# -----------------------------
def zpa_get_all(endpoint, token, page_size=500):
    all_items = []
    page = 1
    total_pages = None
    total_count = None

    while True:
        url = f"{ZPA_CLOUD_URL}{endpoint}?page={page}&pagesize={page_size}"
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }
        resp = requests.get(url, headers=headers, verify=False)
        resp.raise_for_status()
        data = resp.json()

        # On first page, grab metadata
        if total_pages is None:
            total_pages = int(data.get("totalPages", 1))
        if total_count is None:
            total_count = int(data.get("totalCount", 0))
        
        #print(f"total_pages: {total_pages}, total_count: {total_count}")
        
        # Add the list items
        page_items = data.get("list", [])
        all_items.extend(page_items)

        #print(f"Fetched page {page}/{total_pages}, {len(page_items)} items")

        if page >= total_pages:
            break
        page += 1

    return {
        "totalPages": total_pages,
        "totalCount": total_count,
        "list": all_items
    }

def save_scim_groups(token, idpdata, output_dir):
    file_name = "object-scimgroup.json"

    v1_base_path = f"/userconfig/v1/customers/{ZPA_CUSTOMER_ID}"

    datalist = idpdata.get("list", [])
    all_data = []  # List to store all the fetched data
    total_count = 0  # To accumulate the total count of items
    total_pages = 0

    for data in datalist:
        idpid = data["id"]
        endpoint = f"{v1_base_path}/scimgroup/idpId/{idpid}"
        #print("\nendpoint : ", endpoint)
        
        try:
            # Fetch data from the endpoint
            response_data = zpa_get_all(endpoint, token)
            
            total_count += response_data.get("totalCount", 0)
            total_pages += response_data.get("totalPages", 0)
            #print("\ntotal_count : ",total_count)
            #print("total_pages : ",total_pages)
            all_data.extend(response_data.get("list", []))
        
        except Exception as e:
            tb = traceback.format_exc()
            print(f"FAILED: {tb}")
            logger.error(f"FAILED: {tb}")
            zpa_logout(token)
            sys.exit(1)

    if all_data:
        # Once all data is collected, save it to the file
        combined_data = {
            "totalCount": total_count,
            "totalPages": total_pages,
            "list": all_data
        }

        save_json(combined_data, output_dir, file_name)
        print(f"GENERATED_FILE: {file_name}")
        logger.info(f"GENERATED_FILE: {file_name}")

def save_pra_consoles(token, portaldata, output_dir):
    file_name = "object-pra-consoles.json"

    v1_base_path = f"/mgmtconfig/v1/admin/customers/{ZPA_CUSTOMER_ID}/praConsole/praPortal"

    datalist = portaldata.get("list", [])
    all_data = []    # List to store all the fetched data
    total_count = 0  # To accumulate the total count of items
    total_pages = 0

    for data in datalist:
        portalid = data["id"]
        endpoint = f"{v1_base_path}/{portalid}"
        #print("\nendpoint : ", endpoint)
        
        try:
            # Fetch data from the endpoint
            response_data = zpa_get_all(endpoint, token)
            
            total_count += response_data.get("totalCount", 0)
            total_pages += response_data.get("totalPages", 0)
            #print("\ntotal_count : ",total_count)
            #print("total_pages : ",total_pages)
            all_data.extend(response_data.get("list", []))
        
        except Exception as e:
            tb = traceback.format_exc()
            print(f"FAILED: {tb}")
            logger.error(f"FAILED: {tb}")
            zpa_logout(token)
            sys.exit(1)

    if all_data:
        # Once all data is collected, save it to the file
        combined_data = {
            "totalCount": total_count,
            "totalPages": total_pages,
            "list": all_data
        }

        save_json(combined_data, output_dir, file_name)
        print(f"GENERATED_FILE: {file_name}")

# -----------------------------
# FETCH ALL OBJECTS
# -----------------------------
def fetch_all_objects(token, output_dir):
    """
    Fetch various ZPA objects (connectors, groups, segments, servers, etc.)
    and save each object type to its own JSON file.
    """
    
    objects_data_found = False
    
    # Define mapping of API endpoints to output filenames
    object_endpoints = {
        "connector": "object-app-connectors.json",
        "appConnectorGroup": "object-app-connector-groups.json",
        "application": "object-application-segments.json",
        "segmentGroup": "object-segment-groups.json",
        "server": "object-servers.json",
        "serverGroup": "object-server-groups.json",
        "posture": "object-posture.json",
        "idp": "object-idp.json",
        "praPortal": "object-pra-portal.json",
        "praConsole": "object-pra-consoles.json",
        "isolation": "object-isolation-profiles.json",
    }

    v1_base_path = f"/mgmtconfig/v1/admin/customers/{ZPA_CUSTOMER_ID}"
    v2_base_path = f"/mgmtconfig/v2/admin/customers/{ZPA_CUSTOMER_ID}"

    for obj, file_name in object_endpoints.items():
        #print(f"Fetching {obj} …")
        if obj == "idp" or obj == "posture":
            endpoint = f"{v2_base_path}/{obj}"
        elif obj == "isolation":
            endpoint = f"{v1_base_path}/{obj}/profiles"
        else:
            endpoint = f"{v1_base_path}/{obj}"
        
        try:
            data = zpa_get_all(endpoint, token)
            if data is not None:
                objects_data_found = True
                save_json(data, output_dir, file_name)
                print(f"GENERATED_FILE: {file_name}")
                logger.info(f"GENERATED_FILE: {file_name}")
                if file_name == "object-idp.json":
                    save_scim_groups(token, data, output_dir)
        except:
            tb = traceback.format_exc()
            print(f"FAILED: {tb}")
            logger.error(f"FAILED: {tb}")
            continue
    
    return objects_data_found

# -----------------------------
# FETCH ALL POLICIES
# -----------------------------
def fetch_all_policies(token, output_dir):
    
    policies_data_found = False
    
    # Mapping of policy types to output filenames
    policy_type_map = {
        "ACCESS_POLICY": "access-policy.json",
        "TIMEOUT_POLICY": "timeout-policy.json",
        "INSPECTION_POLICY": "inspection-policy.json",
        "ISOLATION_POLICY": "isolation-policy.json",
        "CAPABILITIES_POLICY": "capabilities-policy.json",
        "CREDENTIAL_POLICY": "credential-policy.json",
        "PRIVILEGED_PORTAL_POLICY": "privileged-portal-policy.json",
        "REDIRECTION_POLICY": "redirection-policy.json",
        "CLIENTLESS_SESSION_PROTECTION_POLICY": "clientless-session-protection-policy.json",
        "CLIENT_FORWARDING_POLICY": "client-forwarding-policy.json"
    }

    for policy_type, file_name in policy_type_map.items():
        #print(f"Fetching policies for policy type: {policy_type} …")
        
        endpoint = (
            f"/mgmtconfig/v1/admin/customers/{ZPA_CUSTOMER_ID}"
            f"/policySet/rules/policyType/{policy_type}"
        )
        
        try:
            # If you have a pagination helper (zpa_get_all), use it
            policies = zpa_get_all(endpoint, token)
            if policies is not None:
                policies_data_found = True
                save_json(policies, output_dir, file_name)
                print(f"GENERATED_FILE: {file_name}")
                logger.info(f"GENERATED_FILE: {file_name}")
        except:
            tb = traceback.format_exc()
            print(f"FAILED: {tb}")
            logger.error(f"FAILED: {tb}")
            continue
    
    return policies_data_found

def fetch_and_save_zia_data(session, base_url, endpoint):
    url = f"{base_url}{endpoint}"
    response = session.get(url, timeout=30)
    
    if response.status_code == 200:
        data = response.json()
        return data
    else:
        return None

def save_sublocations(session, ZIA_CLOUD_URL, locationdata, output_dir):
    file_name = "sublocations.json"
    
    v1_base_path = f"/api/v1/locations"
    
    all_data = []
    
    for data in locationdata:
        locationid = data["id"]
        endpoint = f"{v1_base_path}/{locationid}/sublocations"
        try:
            # Fetch data from the endpoint
            response_data =  fetch_and_save_zia_data(session, ZIA_CLOUD_URL, endpoint)
            all_data.extend(response_data)
        except Exception as e:
            tb = traceback.format_exc()
            print(f"FAILED: {tb}")
            logger.error(f"FAILED: {tb}")
            return
    
    if all_data:
        save_json(all_data, output_dir, file_name)
        print(f"GENERATED_FILE: {file_name}")
        logger.info(f"GENERATED_FILE: {file_name}")

def fetch_all_zia_objects(session, ZIA_CLOUD_URL, output_dir):
    """
    Fetch all required ZIA objects and save them as JSON files.
    """
    
    objects_data_found  = False
    
    ZIA_OBJECT_ENDPOINTS = {
        "source_ip_groups": {
            "endpoint": "/api/v1/ipSourceGroups",
            "file": "source_ip_groups.json",
        },
        "source_ipv6_groups": {
            "endpoint": "/api/v1/ipSourceGroups/ipv6SourceGroups",
            "file": "source_ip6_groups.json",
        },
        "destination_ip_groups": {
            "endpoint": "/api/v1/ipDestinationGroups",
            "file": "destination_ip_groups.json",
        },
        "destination_ipv6_groups": {
            "endpoint": "/api/v1/ipDestinationGroups/ipv6DestinationGroups",
            "file": "destination_ip6_groups.json",
        },
        "network_applications": {
            "endpoint": "/api/v1/networkApplications",
            "file": "network_applications.json",
        },
        "network_application_groups": {
            "endpoint": "/api/v1/networkApplicationGroups",
            "file": "network_applications_groups.json",
        },
        "network_services": {
            "endpoint": "/api/v1/networkServices",
            "file": "network_services.json",
        },
        "network_service_groups": {
            "endpoint": "/api/v1/networkServiceGroups",
            "file": "network_services_groups.json",
        },
        "url_categories": {
            "endpoint": "/api/v1/urlCategories",
            "file": "url_categories.json",
        },
        "custom_file_types": {
            "endpoint": "/api/v1/customFileTypes",
            "file": "filetype_control.json",
        },
        "locations": {
            "endpoint": "/api/v1/locations",
            "file": "locations.json",
        },
        "location_groups": {
            "endpoint": "/api/v1/locations/groups",
            "file": "locations_groups.json",
        },
        "device_groups": {
            "endpoint": "/api/v1/deviceGroups",
            "file": "deviceGroups.json",
        },
        "departments": {
            "endpoint": "/api/v1/departments",
            "file": "departments.json",
        },
        "groups": {
            "endpoint": "/api/v1/groups",
            "file": "groups.json",
        },
        "dlp_engines": {
            "endpoint": "/api/v1/dlpEngines",
            "file": "dlpEngines.json",
        },
        "dlp_Dictionaries": {
            "endpoint": "/api/v1/dlpDictionaries",
            "file": "dlpDictionaries.json",
        },
        "users": {
            "endpoint": "/api/v1/users",
            "file": "users.json",
        },
        "emailRecipientProfile": {
            "endpoint": "/api/v1/emailRecipientProfile",
            "file": "object_email_recipient_profile.json",
        }
    }
    
    ZIA_GROUPED_ENDPOINTS = {
        "malware_policy": {
            "file": "object_malware_policy.json",
            "endpoints": {
                "atpMalwareInspection": "/api/v1/cyberThreatProtection/atpMalwareInspection",
                "atpMalwareProtocols": "/api/v1/cyberThreatProtection/atpMalwareProtocols",
                "malwareSettings": "/api/v1/cyberThreatProtection/malwareSettings",
                "malwarePolicy": "/api/v1/cyberThreatProtection/malwarePolicy",
                "mobileAdvanceThreatSettings": "/api/v1/mobileAdvanceThreatSettings"
            }
        },
        "browser_control_policy": {
            "file": "object_browser_control.json",
            "endpoints": {
                "browserControlSettings": "/api/v1/browserControlSettings"
            }
        },
        "advanced_threat_policy": {
            "file": "object_advanced_threat.json",
            "endpoints": {
                "advancedThreatSettings": "/api/v1/cyberThreatProtection/advancedThreatSettings",
                "maliciousUrls": "/api/v1/cyberThreatProtection/maliciousUrls",
                "securityExceptions": "/api/v1/cyberThreatProtection/securityExceptions"
            }
        },
        "saas_security_policy": {
            "file": "object_sass_security.json",
            "endpoints": {
                "casbDlpRules": "/api/v1/casbDlpRules/all",
                "casbMalwareRules": "/api/v1/casbMalwareRules/all"
            }
        },
        "advanced_settings_policy": {
            "file": "object_advanced_settings.json",
            "endpoints": {
                "advancedSettings": "/api/v1/advancedSettings",
                "sandboxRules": "/api/v1/sandboxRules"
            }
        },
        "security_settings":{
            "file": "object_security_settings.json",
            "endpoints": {
                "allowlist": "/api/v1/security",
                "blacklist": "/api/v1/security/advanced"
            }
        },
        "other_settings":{
            "file": "object_other_settings.json",
            "endpoints": {
                "sslInspectionRules": "/api/v1/sslInspectionRules",
                "advancedUrlFilterAndCloudAppSettings": "/api/v1/advancedUrlFilterAndCloudAppSettings"
            }
        }
    }
    
    for name, cfg in ZIA_OBJECT_ENDPOINTS.items():
        try:
            file_name = cfg["file"]
            endpoint  = cfg["endpoint"]
            data = None
            data = fetch_and_save_zia_data(session, ZIA_CLOUD_URL, endpoint)
            if data is not None:
                objects_data_found = True
                save_json(data, output_dir, file_name)
                print(f"GENERATED_FILE: {file_name}")
                logger.info(f"GENERATED_FILE: {file_name}")
                if file_name == "locations.json":
                    save_sublocations(session, ZIA_CLOUD_URL, data, output_dir)

        except Exception:
            tb = traceback.format_exc()
            print(f"FAILED: {tb}")
            logger.error(f"FAILED: {tb}")
    
    for group_name, cfg in ZIA_GROUPED_ENDPOINTS.items():
        try:
            grouped_data = {}
            for key, endpoint in cfg["endpoints"].items():
                data = fetch_and_save_zia_data(session, ZIA_CLOUD_URL, endpoint)
                if data is not None:
                    grouped_data[key] = data
            
            if grouped_data:
                objects_data_found = True
                save_json(grouped_data, output_dir, cfg["file"])
                print(f"GENERATED_FILE: {cfg['file']}")
                logger.info(f"GENERATED_FILE: {cfg['file']}")
        
        except Exception:
            tb = traceback.format_exc()
            print(f"FAILED GROUP: {tb}")
            logger.error(f"FAILED GROUP: {tb}")
    
    return objects_data_found

def extract_all_zia_configs(file_dir, input_dir_name):
    
    objects_data_found  = False
    policies_data_found = False
    
    try:
        timestamp, obfuscated_key = obfuscateApiKey()
        
        if timestamp and obfuscated_key:
        
            #print(obfuscated_key)
            
            # --- Authenticate ---
            login_url = f"{ZIA_CLOUD_URL}/api/v1/authenticatedSession"
            
            payload = {
                "username": ZIA_USERNAME,
                "password": ZIA_PASSWORD,
                "apiKey": obfuscated_key,
                "timestamp": timestamp
            }
            
            session = requests.Session()
            #print("Payload being sent:", payload)
            response = session.post(login_url, json=payload)
            if response.status_code == 200 and 'JSESSIONID' in session.cookies.get_dict():
                print("ZIA_AUTHENTICATED_SUCCESSFULLY")
                logger.info(f"ZIA Authentication successfull")
            else:
                print("ZIA_LOGIN_FAILED")
                logger.error(f"ZIA Login Failed: HTTP {response.status_code} — {response.text}")
                return False, None

    except Exception as e:
        print("FAILED_TO_ESTABLISH_ZIA_CONNECTION")
        logger.error(f"Failed to establish ZIA connection")
        return False, None
        
    # Create 'input' directory
    input_dir_path = os.path.join(file_dir, input_dir_name)
    os.makedirs(input_dir_path, exist_ok=True)

    #print("\ninput_dir : ",input_dir)
    
    # Create 'zia' directory inside 'input'
    zia_output_dir = os.path.join(input_dir_path, "zia")
    os.makedirs(zia_output_dir, exist_ok=True)
    #print("\nZIA output directory:", zia_output_dir)
    
    if INDIVIDUAL_JSONS:
        objects_data_found = fetch_all_zia_objects(session, ZIA_CLOUD_URL, zia_output_dir)
    
    if JSONS_ZIP:
        # Generate a timestamped filename with full path
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_filename = os.path.join(zia_output_dir, f"policies_{timestamp}.zip")
        
        policy_types = ["BA", "FILETYPE_CONTROL", "BANDWIDTH_CONTROL", "MOBILE_APP_RULE", "URL_FILTERING", "CUSTOM_CAPP", "FIREWALL", "DNAT", "DNS", "INTRUSION_PREVENTION", "EMAIL_DLP", "WEB_DLP", "FORWARDING", "SSLPOL"]
        zip_bytes, err = export_policies(session, ZIA_CLOUD_URL, policy_types, zia_output_dir, output_path = output_filename)
        if err:
            print("ERROR_FETCHING_INPUT_ZIP_FILE")
            logger.error("Error fetching ZIA policies input zip file")
        else:
            policies_data_found = True
    
    if objects_data_found == True or policies_data_found == True:
        return True, input_dir_path
        
def extract_all_zpa_configs(file_dir, input_dir_name):
    
    # ZPA Login
    token = zpa_authenticate()
    if token == None:
        return False, None
    #print("\ntoken : ",token)
    
    input_dir_path = os.path.join(file_dir, input_dir_name)
    os.makedirs(input_dir_path, exist_ok=True)
    
    # Create 'zpa' directory inside 'input'
    zpa_output_dir = os.path.join(input_dir_path, "zpa")
    os.makedirs(zpa_output_dir, exist_ok=True)
    #print("\nZPA output directory:", zpa_output_dir)
    
    objects_data_found  = False
    policies_data_found = False
    
    # ~ # Extract ZPA objects
    # ~ objects_data_found = fetch_all_objects(token, zpa_output_dir)
    
    # ~ # Extract ZPA policies
    # ~ policies_data_found = fetch_all_policies(token, zpa_output_dir)
    
    # ZPA Logout
    zpa_logout(token)
    
    # ~ print("\nobjects_data_found : ",objects_data_found)
    # ~ print("policies_data_found : ",policies_data_found)
    
    if objects_data_found == True or policies_data_found == True:
        return True, input_dir_path
    
    return False,None

def main():
    global ZIA_CLOUD_URL
    global ZIA_USERNAME
    global ZIA_PASSWORD
    global ZIA_API_KEY 
    global ZPA_USERNAME
    global ZPA_PASSWORD
    global ZPA_CUSTOMER_ID
    global ZPA_CLOUD_URL
    global logger
    
    parser = argparse.ArgumentParser(description="Fetch configuration data from Zscaler ZIA (Zscaler Internet Access)")
    
    file_dir = os.path.dirname(os.path.abspath(__file__))
    #print("\n\nfile_dir : ",file_dir)
    
    log_filename = f"log_fetch_{datetime.now().strftime('%Y%m%d')}.log"
    log_filepath = os.path.join(file_dir, log_filename)
    logger = setup_logger(log_filepath)
    
    zia_config_status = False
    zpa_config_status = False
    
    # Create 'input' directory
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    input_dir_name = f"zs_config_{timestamp}"
    
    zia_answer = input("Fetch ZIA configuration? (y/n) : ")
    if zia_answer != "y" and zia_answer != "n":
        print("Wrong choice entered. Selecting 'n' by default")
        logger.info("Wrong choice entered. Selecting 'n' by default")
    
    try:
        if zia_answer == "y":
            ZIA_CLOUD_URL = input("Enter ZIA Cloud URL : ")
            ZIA_USERNAME  = input("Enter ZIA username : ")
            ZIA_PASSWORD  = pwinput.pwinput("Enter ZIA password : ")
            ZIA_API_KEY   = pwinput.pwinput("Enter ZIA API key : ")
            validate_credentials("ZIA")
    except KeyboardInterrupt:
        print("\nCancelled by user. Exiting.")
        logger.info("Cancelled by user. Exiting.")
        exit(1)
        
    zpa_answer = input("\nFetch ZPA configuration? (y/n) : ")
    if zpa_answer != "y" and zpa_answer != "n":
        print("Wrong choice entered. Selecting 'n' by default")
        logger.info("Wrong choice entered. Selecting 'n' by default")
        
    try:
        if zpa_answer == "y":
            ZPA_CLOUD_URL   = input("Enter ZPA Cloud URL : ")
            ZPA_CUSTOMER_ID = input("Enter ZPA customer ID : ")
            ZPA_USERNAME    = input("Enter ZPA client ID : ")
            ZPA_PASSWORD    = pwinput.pwinput("Enter ZPA client secret : ")
            validate_credentials("ZPA")
    except KeyboardInterrupt:
        print("\nCancelled by user. Exiting.")
        logger.info("Cancelled by user. Exiting.")
        exit(1)
    
    if zia_answer == "y":
        start_time = datetime.now()
        print(f"{'-'*100}")
        print(f"ZIA configuration extraction process started at: {start_time}")
        logger.info(f"ZIA configuration extraction process started at: {start_time}")
        
        zia_config_status, input_dir_path = extract_all_zia_configs(file_dir, input_dir_name)
        
        end_time = datetime.now()
        print(f"ZIA configuration extraction process ended at: {start_time}")
        print(f"Total execution time: {end_time - start_time}")
        logger.info(f"ZIA configuration extraction process ended at: {start_time}")
        logger.info(f"Total execution time: {end_time - start_time}")
        print(f"{'-'*100}")
        
    if zpa_answer == "y":
        start_time = datetime.now()
        print(f"{'-'*100}")
        print(f"ZPA configuration extraction process started at: {start_time}")
        logger.info(f"ZPA configuration extraction process started at: {start_time}")
        
        zpa_config_status, input_dir_path = extract_all_zpa_configs(file_dir, input_dir_name)
        
        end_time = datetime.now()
        print(f"ZPA configuration extraction process ended at: {start_time}")
        print(f"Total execution time: {end_time - start_time}")
        logger.info(f"ZPA configuration extraction process ended at: {start_time}")
        logger.info(f"Total execution time: {end_time - start_time}")
        print(f"{'-'*100}")
    
    #print("\nzia_config_status : ",zia_config_status)
    #print("zpa_config_status : ",zpa_config_status)
    
    if zia_config_status == True or zpa_config_status == True:
        input_dir_name = os.path.basename(input_dir_path)
        
        shutil.make_archive(
            base_name=input_dir_path,
            format="zip",
            root_dir=file_dir,
            base_dir=input_dir_name
        )
        print(f"Zscaler config zip created: {input_dir_name}.zip")
        logger.info(f"Zscaler config zip created: {input_dir_name}.zip")
        
if __name__ == "__main__":
    main()
