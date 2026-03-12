import os
import time
import requests

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def fetch_nvd_cve(cve_id: str) -> dict:
    """
    NVD API에서 CVE 상세 정보를 조회하여 반환.
    BDSA- 등 NVD에 없는 ID는 빈 dict 반환.
    """
    if not cve_id.upper().startswith("CVE-"):
        return {}

    headers = {}
    api_key = os.getenv("NVD_API_KEY")
    if api_key:
        headers["apiKey"] = api_key

    try:
        res = requests.get(
            NVD_API_BASE,
            params={"cveId": cve_id},
            headers=headers,
            timeout=10,
        )
        res.raise_for_status()
        data = res.json()

        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            return {}

        cve = vulnerabilities[0].get("cve", {})
        return _parse_cve(cve)

    except Exception as e:
        print(f"  [NVD] {cve_id} 조회 실패: {e}")
        return {}


def _parse_cve(cve: dict) -> dict:
    """CVE 응답에서 설명 및 버전 픽스 정보 추출."""
    # 영문 설명
    description = ""
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            description = d.get("value", "")
            break

    # CVSS 점수
    cvss_score = None
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if key in metrics and metrics[key]:
            cvss_score = metrics[key][0].get("cvssData", {}).get("baseScore")
            break

    # 영향받는 버전 범위 (CPE configurations)
    affected_versions = _extract_affected_versions(cve.get("configurations", []))

    return {
        "description": description,
        "cvss_score": cvss_score,
        "affected_versions": affected_versions,
    }


def _extract_affected_versions(configurations: list) -> list:
    """CPE matchCriteria에서 버전 범위 정보 추출."""
    results = []
    for config in configurations:
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if not match.get("vulnerable"):
                    continue

                info = {}
                cpe = match.get("criteria", "")
                # cpe:2.3:a:vendor:product:version:...
                parts = cpe.split(":")
                if len(parts) >= 5:
                    info["product"] = f"{parts[3]}:{parts[4]}"

                for field in (
                    "versionStartIncluding",
                    "versionStartExcluding",
                    "versionEndIncluding",
                    "versionEndExcluding",
                ):
                    if match.get(field):
                        info[field] = match[field]

                if info:
                    results.append(info)

    return results


def enrich_with_nvd(critical_list: list, delay: float = 0.6) -> list:
    """
    취약점 목록에 NVD 정보를 추가하여 반환.
    NVD API rate limit 대응을 위해 요청 간 delay(초) 적용.
    (API 키 없을 때 30초당 5건 제한 → 약 0.6초 간격)
    """
    enriched = []
    seen_cves = {}

    for item in critical_list:
        cve_id = item.get("Vulnerability", "")
        if cve_id in seen_cves:
            nvd_info = seen_cves[cve_id]
        else:
            print(f"  [NVD] {cve_id} 조회 중...")
            nvd_info = fetch_nvd_cve(cve_id)
            seen_cves[cve_id] = nvd_info
            time.sleep(delay)

        enriched.append({**item, "nvd": nvd_info})

    return enriched
