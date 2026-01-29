# Secure Cloud Retail Analytics Dashboard

This project demonstrates a secure, cloud-native analytics platform designed for the retail sector. [cite_start]It features a robust **Role-Based Access Control (RBAC)** system and implements **Differential Privacy (DP)** via Laplace noise to protect sensitive figures in public-facing dashboards[cite: 1, 2, 4].

[cite_start]Originally deployed on a **Google Cloud VM** using **Nginx**, **Gunicorn**, and **Flask**, this repository now serves as a technical showcase of the system's architecture and privacy-preserving capabilities[cite: 55, 65, 133].

## 📂 Project Documentation
[cite_start]For a comprehensive breakdown of the architecture, privacy trade-offs, and deployment configuration, please refer to the full report pdf.

---

## 🛠️ Key Technical Features

### 1. Privacy Engineering: Differential Privacy
[cite_start]To protect exact profit figures—particularly for small transaction counts—the system integrates a **Laplace Noise Mechanism**[cite: 25, 43, 60]. 
* [cite_start]**Privacy Budget ($\epsilon$):** Set at **0.01** to achieve a "sweet spot" where data utility remains high for business insights while individual figures are effectively blurred[cite: 26, 63, 798].
* [cite_start]**Enforcement:** Differential Privacy is forced "Always On" for Data Analysts but remains optional for Managers who may require exact figures for internal auditing or presentations[cite: 50, 51, 86, 87].

### 2. Identity and Access Management (IAM)
[cite_start]The system employs a strict RBAC model to ensure data is accessed only by authorised personnel during appropriate times[cite: 33, 78].

| Role | Access Hours | Token Lifetime | Tab Visibility | DP Status |
| :--- | :--- | :--- | :--- | :--- |
| **Data Analyst** | 09:00 - 17:00 | 30 Seconds | Analytics Only | [cite_start]Forced ON [cite: 76, 80, 82, 86] |
| **Data Manager** | 24 Hours | 10 Minutes | All Tabs | [cite_start]Optional [cite: 76, 81, 84, 87] |
| **Security Officer** | 24 Hours | 10 Minutes | Audit Log Only | [cite_start]N/A [cite: 76, 81, 83, 88] |

### 3. Security Infrastructure
* [cite_start]**Authentication:** Uses **JWT (HS256)** tokens signed with a secret key to ensure identity and prevent tampering[cite: 38, 56, 57, 58].
* [cite_start]**Password Security:** Credentials are hashed using **bcrypt** to ensure secure storage[cite: 59, 65].
* [cite_start]**Immutable Auditing:** A secure, append-only audit log records every login attempt, including time, role, and action, for supervision by the security team[cite: 61, 89, 113].

---

## 📊 Analytics Showcase

[cite_start]The dashboard provides primary analytical views derived from the publicly available `Global_superstore2.csv` dataset[cite: 36]:

* [cite_start]**Top Products:** Visualises profitability grouped by region or category[cite: 70].
* [cite_start]**Discount vs Profit Trends:** Interactive charts showing how aggressive discounting impacts the bottom line[cite: 72].
* [cite_start]**Anomaly Overview:** Identifies transactions with unusually high discounts (>50%) or low profit (<$100)[cite: 73].

---

## 🏗️ Technical Stack
* [cite_start]**Cloud Platform:** Google Cloud Platform (BigQuery & Compute Engine)[cite: 54, 114].
* [cite_start]**Backend:** Flask (Python)[cite: 65, 95].
* [cite_start]**Frontend:** Bootstrap & Chart.js for interactive visualisations[cite: 45, 62, 115].
* [cite_start]**Web Server:** Nginx & Gunicorn production server[cite: 133, 135].

---

## ⚠️ Security Disclaimer
[cite_start]Sensitive configuration files, including the `.env` file and Google Cloud `service-account.json` keys, have been omitted from this repository to adhere to security best practices and prevent unauthorised access to cloud resources[cite: 90, 131, 132].
