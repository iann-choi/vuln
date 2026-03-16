from typing import Dict, List


def fetch_blackduck_advisory(base_url: str, session, vuln_name: str) -> dict:
    """BlackDuck API에서 취약점 상세 정보 조회."""
    url = f"{base_url}/api/vulnerabilities/{vuln_name}"
    try:
        res = session.get(url, timeout=10)
        res.raise_for_status()
        return _parse_advisory(res.json())
    except Exception as e:
        print(f"  [BlackDuck Advisory] {vuln_name} 조회 실패: {e}")
        return {}


def _parse_advisory(data: dict) -> dict:
    """BlackDuck 취약점 응답에서 필요한 필드 추출."""
    cvss3 = data.get("cvss3") or {}
    cvss2 = data.get("cvss2") or {}

    return {
        "description": data.get("description", ""),
        "solution": data.get("solution", ""),
        "workaround": data.get("workaround", ""),
        "cvss_score": cvss3.get("baseScore") or cvss2.get("baseScore"),
        "severity": data.get("severity", ""),
        "published_date": data.get("publishedDate", ""),
    }


def fetch_upgrade_guidance(session, component_version_href: str) -> dict:
    """BlackDuck API에서 컴포넌트 업그레이드 권고 버전 조회."""
    if not component_version_href:
        return {}
    url = f"{component_version_href}/upgrade-guidance"
    try:
        res = session.get(url, timeout=10)
        res.raise_for_status()
        data = res.json()
        short_term = (data.get("shortTerm") or {}).get("versionName", "")
        long_term = (data.get("longTerm") or {}).get("versionName", "")
        return {
            "short_term_version": short_term,
            "long_term_version": long_term,
        }
    except Exception as e:
        print(f"  [BlackDuck Upgrade] 업그레이드 정보 조회 실패: {e}")
        return {}


def enrich_with_blackduck(auth_instance, critical_list: List[Dict]) -> List[Dict]:
    """취약점 목록에 BlackDuck Advisory 및 upgrade guidance 정보를 추가하여 반환."""
    base_url = auth_instance.base_url
    session = auth_instance.session
    enriched = []
    seen_vuln = {}
    seen_upgrade = {}

    for item in critical_list:
        vuln_name = item.get("Vulnerability", "")
        component_version_href = item.get("Component_Version_Href", "")

        if vuln_name in seen_vuln:
            bd_info = seen_vuln[vuln_name]
        else:
            print(f"  [BlackDuck Advisory] {vuln_name} 조회 중...")
            bd_info = fetch_blackduck_advisory(base_url, session, vuln_name)
            seen_vuln[vuln_name] = bd_info

        if component_version_href in seen_upgrade:
            upgrade_info = seen_upgrade[component_version_href]
        else:
            print(f"  [BlackDuck Upgrade] {item.get('Component')} 업그레이드 정보 조회 중...")
            upgrade_info = fetch_upgrade_guidance(session, component_version_href)
            seen_upgrade[component_version_href] = upgrade_info

        enriched.append({**item, "blackduck": {**bd_info, **upgrade_info}})

    return enriched
