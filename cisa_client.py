import requests
from typing import Dict, List

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

_kev_cache: Dict[str, Dict] = {}


def _load_kev() -> Dict[str, Dict]:
    """CISA KEV 전체 목록을 다운로드하여 CVE ID → 항목 딕셔너리로 반환."""
    global _kev_cache
    if _kev_cache:
        return _kev_cache

    try:
        print("  [CISA] KEV 목록 다운로드 중...")
        res = requests.get(CISA_KEV_URL, timeout=15)
        res.raise_for_status()
        vulns = res.json().get("vulnerabilities", [])
        _kev_cache = {v["cveID"]: v for v in vulns if "cveID" in v}
        print(f"  [CISA] KEV 목록 로드 완료 ({len(_kev_cache)}개)")
    except Exception as e:
        print(f"  [CISA] KEV 목록 로드 실패: {e}")
        _kev_cache = {}

    return _kev_cache


def fetch_cisa_kev(cve_id: str) -> Dict:
    """CVE ID가 CISA KEV에 등재되어 있으면 관련 정보를 반환, 없으면 빈 dict."""
    if not cve_id.upper().startswith("CVE-"):
        return {}

    kev = _load_kev()
    entry = kev.get(cve_id.upper())
    if not entry:
        return {}

    return {
        "actively_exploited": True,
        "vendor_project": entry.get("vendorProject", ""),
        "product": entry.get("product", ""),
        "short_description": entry.get("shortDescription", ""),
        "due_date": entry.get("dueDate", ""),
        "ransomware_use": entry.get("knownRansomwareCampaignUse", "Unknown"),
    }


def enrich_with_cisa(critical_list: List[Dict]) -> List[Dict]:
    """취약점 목록에 CISA KEV 정보를 추가하여 반환."""
    kev = _load_kev()
    if not kev:
        return [{**item, "cisa": {}} for item in critical_list]

    enriched = []
    for item in critical_list:
        cve_id = item.get("Vulnerability", "").upper()
        cisa_info = fetch_cisa_kev(cve_id)
        if cisa_info:
            ransomware = cisa_info.get("ransomware_use", "Unknown")
            flag = " [랜섬웨어 악용]" if ransomware == "Known" else ""
            print(f"  [CISA] {cve_id} → KEV 등재 (실제 공격 확인){flag}")
        enriched.append({**item, "cisa": cisa_info})

    return enriched
