import requests
from typing import Dict, List

EPSS_API_BASE = "https://api.first.org/data/1.0/epss"


def fetch_epss(cve_ids: List[str]) -> Dict[str, Dict]:
    """CVE ID 목록의 EPSS 점수를 일괄 조회."""
    cve_ids = [c for c in cve_ids if c.upper().startswith("CVE-")]
    if not cve_ids:
        return {}

    try:
        res = requests.get(
            EPSS_API_BASE,
            params={"cve": ",".join(cve_ids)},
            timeout=10,
        )
        res.raise_for_status()
        return {
            item["cve"].upper(): {
                "epss": float(item["epss"]),
                "percentile": float(item["percentile"]),
            }
            for item in res.json().get("data", [])
        }
    except Exception as e:
        print(f"  [EPSS] 조회 실패: {e}")
        return {}


def enrich_with_epss(critical_list: List[Dict]) -> List[Dict]:
    """취약점 목록에 EPSS 점수를 추가하여 반환."""
    cve_ids = list({
        item["Vulnerability"]
        for item in critical_list
        if item.get("Vulnerability", "").upper().startswith("CVE-")
    })

    print(f"  [EPSS] {len(cve_ids)}개 CVE 점수 조회 중...")
    scores = fetch_epss(cve_ids)

    enriched = []
    for item in critical_list:
        vuln_id = item.get("Vulnerability", "").upper()
        enriched.append({**item, "epss": scores.get(vuln_id, {})})

    return enriched
