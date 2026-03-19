import os
import requests
from typing import Dict, List

GITHUB_ADVISORY_URL = "https://api.github.com/advisories"


def _get_headers() -> Dict:
    headers = {"Accept": "application/vnd.github+json"}
    token = os.getenv("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _parse_advisory(data: dict) -> dict:
    """GitHub Advisory 응답에서 필요한 필드 추출."""
    cvss_score = None
    cvss_info = data.get("cvss")
    if cvss_info:
        cvss_score = cvss_info.get("score")

    # 패키지별 영향 버전 및 수정 버전 추출
    fix_versions = []
    affected_packages = []
    for vuln in data.get("vulnerabilities", []):
        pkg = vuln.get("package", {})
        pkg_name = pkg.get("name", "")
        ecosystem = pkg.get("ecosystem", "")
        vulnerable_range = vuln.get("vulnerable_version_range", "")
        first_patched = vuln.get("first_patched_version", "")

        if first_patched and first_patched not in fix_versions:
            fix_versions.append(first_patched)

        if pkg_name:
            affected_packages.append({
                "package": f"{ecosystem}:{pkg_name}" if ecosystem else pkg_name,
                "vulnerable_range": vulnerable_range,
                "first_patched_version": first_patched,
            })

    return {
        "ghsa_id": data.get("ghsa_id", ""),
        "summary": data.get("summary", ""),
        "description": data.get("description", ""),
        "severity": data.get("severity", ""),
        "cvss_score": cvss_score,
        "fix_versions": fix_versions,
        "affected_packages": affected_packages,
    }


def fetch_github_advisory(cve_id: str) -> dict:
    """CVE ID로 GitHub Advisory DB를 조회하여 반환."""
    if not cve_id.upper().startswith("CVE-"):
        return {}

    try:
        res = requests.get(
            GITHUB_ADVISORY_URL,
            params={"cve_id": cve_id},
            headers=_get_headers(),
            timeout=10,
        )
        if res.status_code == 404:
            return {}
        if res.status_code == 403:
            print(f"  [GitHub] rate limit 초과. GITHUB_TOKEN을 .env에 추가하면 해결됩니다.")
            return {}
        res.raise_for_status()

        results = res.json()
        if not results:
            return {}

        return _parse_advisory(results[0])

    except Exception as e:
        print(f"  [GitHub] {cve_id} 조회 실패: {e}")
        return {}


def enrich_with_github(critical_list: List[Dict]) -> List[Dict]:
    """취약점 목록에 GitHub Advisory 정보를 추가하여 반환."""
    enriched = []
    seen: Dict[str, dict] = {}

    for item in critical_list:
        cve_id = item.get("Vulnerability", "")
        if cve_id in seen:
            gh_info = seen[cve_id]
        else:
            print(f"  [GitHub] {cve_id} 조회 중...")
            gh_info = fetch_github_advisory(cve_id)
            seen[cve_id] = gh_info

        enriched.append({**item, "github": gh_info})

    return enriched
