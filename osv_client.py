import requests
from typing import Dict, List

OSV_API_BASE = "https://api.osv.dev/v1"


def _parse_osv(data: dict) -> dict:
    """OSV 응답에서 필요한 필드 추출."""
    fix_versions = []
    for affected in data.get("affected", []):
        for rng in affected.get("ranges", []):
            for event in rng.get("events", []):
                if "fixed" in event:
                    fix_versions.append(event["fixed"])

    return {
        "id": data.get("id", ""),
        "aliases": data.get("aliases", []),
        "summary": data.get("summary", ""),
        "details": data.get("details", ""),
        "fix_versions": list(set(fix_versions)),
        "references": [r.get("url") for r in data.get("references", []) if r.get("url")],
    }


def _fetch_by_id(vuln_id: str) -> dict:
    """CVE/GHSA ID로 OSV 직접 조회."""
    try:
        res = requests.get(f"{OSV_API_BASE}/vulns/{vuln_id}", timeout=10)
        if res.status_code == 404:
            return {}
        res.raise_for_status()
        return _parse_osv(res.json())
    except Exception as e:
        print(f"  [OSV] {vuln_id} ID 조회 실패: {e}")
        return {}


def _fetch_by_package(component: str, version: str) -> list:
    """패키지명 + 버전으로 OSV 취약점 목록 조회 (npm 기준)."""
    try:
        payload = {
            "package": {
                "name": component.lower(),
                "ecosystem": "npm",
            },
            "version": version,
        }
        res = requests.post(f"{OSV_API_BASE}/query", json=payload, timeout=10)
        res.raise_for_status()
        return [_parse_osv(v) for v in res.json().get("vulns", [])]
    except Exception as e:
        print(f"  [OSV] {component} {version} 패키지 조회 실패: {e}")
        return []


def fetch_osv(vuln_id: str, component: str, version: str) -> dict:
    """취약점 ID 또는 패키지+버전으로 OSV 정보 조회."""
    # CVE/GHSA는 ID로 직접 조회
    if vuln_id.upper().startswith(("CVE-", "GHSA-")):
        result = _fetch_by_id(vuln_id)
        if result:
            return result

    # BDSA 또는 ID 조회 실패 시 패키지+버전으로 조회
    vulns = _fetch_by_package(component, version)
    if not vulns:
        return {}

    # vuln_id와 alias 매칭
    for v in vulns:
        if vuln_id in v.get("aliases", []) or vuln_id == v.get("id"):
            return v

    # 매칭 안되면 첫 번째 결과 반환
    return vulns[0]


def enrich_with_osv(critical_list: List[Dict]) -> List[Dict]:
    """취약점 목록에 OSV 정보를 추가하여 반환."""
    enriched = []
    seen = {}

    for item in critical_list:
        vuln_id = item.get("Vulnerability", "")
        component = item.get("Component", "")
        version = item.get("Component_Version", "")

        cache_key = (vuln_id, component, version)
        if cache_key in seen:
            osv_info = seen[cache_key]
        else:
            print(f"  [OSV] {vuln_id} ({component} {version}) 조회 중...")
            osv_info = fetch_osv(vuln_id, component, version)
            seen[cache_key] = osv_info

        enriched.append({**item, "osv": osv_info})

    return enriched
