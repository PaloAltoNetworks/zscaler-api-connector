# How to Generate and Setup the API Parameters

## ZIA Account

For ZIA below parameters are required:

- Cloud URL (e.g., https://admin.zscaler.net)
- Zscaler Admin Username
- Zscaler Admin Password
- Zscaler API Key

### Cloud URL

To determine your ZIA cloud URL for API access, you must retrieve it from within the Zscaler Internet Access (ZIA) Admin Portal.

**Steps to Find Your ZIA Cloud URL**

1. **Log in** to your ZIA Admin Portal.
2. **Navigate** to **Administration** > **Cloud Service API Security**.
3. **View** the **Cloud Service API Key** tab or the **OAuth 2.0 Authorization Servers** tab. The base URL for your organization's cloud is displayed there.

The URL is specific to the Zscaler cloud on which your organization's account is provisioned (e.g., example.zscaler.net, example.zscloud.net, example.zscalerone.net).

### Zscaler Admin Username

This is the ZIA admin username.

### Zscaler Admin Password

This is the ZIA admin password.

> **Note:**
> - The admin user should use the normal password-based authentication and not SAML Authentication
> - The Superuser role should be assigned to the admin

### Zscaler API Key

1. Navigate to **Administration** > **Cloud Service API Security** > **Cloud Service API Key**.
2. On the **Cloud Service API Key** page, you may need to delete any existing key if your organization has a limit, before adding a new one.
3. Click **Add API Key** (or similar option). You will be prompted to set parameters like status (Enabled) and session validity interval.
4. Click **Save**.
5. **Copy the generated key (client secret)** immediately. For security reasons, the key is only displayed once and is not available to view again after you close the window, so store it securely.

---

## ZPA Account

For ZPA below parameters are required:

- Cloud URL (e.g., https://config.private.zscaler.com)
- Customer ID
- Client ID
- Client Secret

### Cloud URL

For cloud URL, determine the cloud FQDN using below steps and use the format as `https://{FQDN}` value in the cloud URL value.

The easiest way to find your cloud name is to look at the URL you use to log in to the ZPA Admin Portal.

Generally your organization's cloud name is the domain name (e.g., **zscalerbeta.net**, **zpatwo.net**).

The API endpoint will be a subdomain of your login URL.

**Examples:**
- If you log in to `admin.zscalerbeta.net`, your API URL is `config.zscalerbeta.net`
- If you log in to `admin.zpatwo.net`, your API URL is `config.zpatwo.net`

For the standard production cloud, the hostname is typically `config.private.zscaler.com`.

**Common hostnames:**
- `config.private.zscaler.com` (Production cloud)
- `config.zpatwo.net` (ZPATWO cloud)
- `config.zscalerbeta.net` (Beta cloud)
- `config.gov.zscaler.com` (Government cloud)

### Client ID and Client Secret

To create an API key in Zscaler Private Access (ZPA), you must use the ZPA Admin Portal. The process involves defining the key's properties and role, then securely copying the generated Client ID and Client Secret.

**Step-by-Step Guide**

1. **Access the ZPA Admin Portal**
   - Log in to your ZPA admin account

2. **Navigate to API Key Management**
   - Go to **Administration** > **Public API** > **API Keys**

   > **Note:** If you do not see the "API Keys" option, you may need to submit a ticket to Zscaler Support to provision API access for your tenant.

3. **Add a New API Key**
   - Click on the **Add API Key** (or simply **Add**) button
   - The configuration window will appear

4. **Configure the API Key Details**

   In the configuration window, provide the following information:
   - **Name:** Enter a descriptive name for the key
   - **Status:** Ensure the key is set to Enabled
   - **Session Validity Interval (In Seconds):** Set the duration the key is valid for use
   - **Role:** Select the appropriate predefined or custom role. The role enforces granular role-based access control (RBAC) on the API operations the key can perform (e.g., API Full Access for complete access)

5. **Save and Copy Credentials**
   - Click **Save**
   - The Client Secret will be displayed on the screen only this one time
   - Immediately copy the **Client ID** and the **Client Secret** to a secure location (e.g., a password manager)
   - For authentication, both the Client ID and Client Secret are required
   - Once you close this window, the client secret can no longer be retrieved from the ZPA Admin Portal. If lost, you will need to regenerate the key

### Customer ID

After creating the key, you will also need your **Customer ID**, which can be copied from the menu on the API Keys page (usually found by clicking the menu icon in the top corner of the table). This ID is necessary when making API calls.
