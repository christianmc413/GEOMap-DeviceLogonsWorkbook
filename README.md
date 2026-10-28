# GEOMap-DeviceLogonsWorkbook
I created a workbook with a visual to show remote IP addresses that are logging into VMs. It shows where on a global map and the color and size determines the number of attempts. 
# Microsoft Sentinel Workbook: Inbound Authentication Origins & Geolocation Mapping

## Overview
This Microsoft Sentinel custom workbook visualizes inbound authentication origins to identify potential brute-force attacks, unauthorized access attempts, and suspicious login activity across managed endpoints. By enriching `DeviceLogonEvents` with native geolocation data, this dashboard maps external IP connections globally—enabling SOC analysts to immediately distinguish between legitimate user activity and high-volume external threats.

---

## Architecture & Data Flow

1. **Log Source**: `DeviceLogonEvents` ingested into Microsoft Sentinel via Defender for Endpoint / Log Analytics agent.
2. **Filtering**: Excludes private/internal IP traffic (`RemoteIPType == "Public"`) and isolates inbound network/RDP sessions (`Network`, `RemoteInteractive`).
3. **Geo-Enrichment**: Evaluates external IP addresses using Sentinel's native `geo_info_from_ip_address()` function (MaxMind GeoLite2 data) to extract latitude, longitude, country, and city coordinates.
4. **Visualization**: Aggregates total attempts, successes, failures, targeted accounts, and distinct target devices into a dynamic bubble map and structured investigation table.

---

## KQL Query Implementation

The map and breakdown table are powered by the following Kusto Query Language (KQL) query:

// === Inbound auth origins (geo) ===
// Goal: plot WHERE remote logons originate, and whether they succeeded.
DeviceLogonEvents
// Only logons that came over the network from a real external address.
// RemoteIPType filters out the huge volume of private/internal logons,
// which would otherwise return empty coordinates and clutter the map.
| where RemoteIPType == "Public"
| where isnotempty(RemoteIP)
// We care about network + remote-interactive (RDP) logons reaching in.
| where LogonType in ("Network", "RemoteInteractive")
// Enrich the source IP with geolocation (country/city/lat/long).
| extend geo = geo_info_from_ip_address(RemoteIP)
| extend Latitude  = toreal(geo.latitude),
         Longitude = toreal(geo.longitude),
         Country   = tostring(geo.country),
         City      = tostring(geo.city)
// Drop rows the geo DB couldn't resolve (no coordinates = nothing to plot).
| where isnotempty(Latitude) and isnotempty(Longitude)
// Aggregate per source location so the map plots one bubble per origin.
// Successes vs failures are counted separately to expose the dangerous mix.
| summarize Attempts        = count(),
            Successes       = countif(ActionType == "LogonSuccess"),
            Failures        = countif(ActionType == "LogonFailed"),
            TargetedDevices = dcount(DeviceName),
            Accounts        = make_set(AccountName, 25)
         by RemoteIP, Country, City, Latitude, Longitude
// Label shown on the bubble: IP + country, plus how many succeeded.
| extend MapLabel = strcat(RemoteIP, " (", Country, ") — ", Successes, " success / ", Attempts, " total")
| project Latitude, Longitude, MapLabel, Attempts, Successes, Failures, TargetedDevices, RemoteIP, Country, City, Accounts
| order by Successes desc, Attempts desc

---

### 1. Inbound Authentication Origins (Global Map View)
The map visualizes external logon origins where bubble **size** represents the total volume of logon attempts, and **color coding** reflects the success-to-failure ratio...

<img width="1472" height="690" alt="image" src="https://github.com/user-attachments/assets/a52ca900-97da-4963-8a9e-72d2595199af" />


### 2. Source IP Breakdown Table
A granular breakdown table sits below the map to assist analysts in triaging high-risk IPs...

<img width="1470" height="512" alt="image" src="https://github.com/user-attachments/assets/e8e3c045-6a57-461c-908a-606e40aabfa9" />

### Case Study 1: Suspicious Brute-Force Activity
* **Target IP**: `80.94.95.83` (Romania) / `211.237.2.246` (South Korea)
* **Activity**: High-volume authentication attempts...

<img width="1691" height="388" alt="image" src="https://github.com/user-attachments/assets/c7aa624e-a23e-4f1c-904f-ba87048dfb70" />
<img width="600" height="838" alt="image" src="https://github.com/user-attachments/assets/a6915a8a-0ae5-4a70-8f06-51c6d523325f" />

### Case Study 2: Normal / Authorized User Access
* **Target IP**: `66.51.113.103` (United States)
* **Activity**: 4 attempts, 4 successes, 0 failures.

<img width="1672" height="421" alt="image" src="https://github.com/user-attachments/assets/c5927f07-4ab6-49ce-a285-580b92d3a094" />
