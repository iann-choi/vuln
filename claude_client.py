import os
import json
from typing import Dict, List

import anthropic

from nvd_client import enrich_with_nvd
from blackduck_advisory_client import enrich_with_blackduck


def _build_prompt(enriched_list: List[Dict]) -> str:
    lines = []
    for idx, item in enumerate(enriched_list, start=1):
        nvd = item.get("nvd") or {}
        bd = item.get("blackduck") or {}
        affected = nvd.get("affected_versions", [])

        version_ranges = []
        for v in affected:
            parts = []
            if v.get("versionStartIncluding"):
                parts.append(f">={v['versionStartIncluding']}")
            if v.get("versionStartExcluding"):
                parts.append(f">{v['versionStartExcluding']}")
            if v.get("versionEndExcluding"):
                parts.append(f"<{v['versionEndExcluding']} (fix: {v['versionEndExcluding']})")
            if v.get("versionEndIncluding"):
                parts.append(f"<={v['versionEndIncluding']}")
            if parts:
                product = v.get("product", "")
                version_ranges.append(f"{product} [{', '.join(parts)}]")

        version_info = "; ".join(version_ranges) if version_ranges else "NVD 버전 정보 없음"
        cvss = nvd.get("cvss_score") or bd.get("cvss_score")
        cvss_str = f"CVSS={cvss}" if cvss else "CVSS=N/A"
        nvd_desc = nvd.get("description", "")
        bd_desc = bd.get("description", "")
        bd_solution = bd.get("solution", "")
        bd_workaround = bd.get("workaround", "")
        bd_short = bd.get("short_term_version", "")
        bd_long = bd.get("long_term_version", "")

        lines.append(
            f"{idx}. "
            f"Project={item.get('Project')}, "
            f"Version={item.get('Version')}, "
            f"Component={item.get('Component')}, "
            f"Component_Version={item.get('Component_Version')}, "
            f"Vulnerability={item.get('Vulnerability')}, "
            f"{cvss_str}, "
            f"NVD_Description={nvd_desc or '없음'}, "
            f"BD_Description={bd_desc or '없음'}, "
            f"BD_ShortTerm_Version={bd_short or 'not available at this time'}, "
            f"BD_LongTerm_Version={bd_long or 'not available at this time'}, "
            f"BD_Workaround={bd_workaround or '없음'}, "
            f"Affected_Versions={version_info}"
        )

    joined = "\n".join(lines)

    return f"""
너는 소프트웨어 보안 전문가이다.

아래는 BlackDuck SCA 결과에서 나온 Critical 취약 컴포넌트 목록이다.
NVD 및 BlackDuck Security Advisor에서 가져온 취약점 정보가 함께 제공된다.

반드시 아래 형식의 **JSON 배열만** 반환해 주세요. (마크다운 코드블록, 설명, 머리말 포함 금지)

[
  {{
    "Project": "...",
    "Version": "...",
    "Component": "...",
    "Component_Version": "...",
    "Vulnerability": "...",
    "Description": "한국어 설명",
    "ShortTermRemediation": "한국어 단기 업그레이드 조치 (구체적 버전 포함)",
    "LongTermRemediation": "한국어 장기 업그레이드 조치",
    "Workaround": "한국어 임시 보호 조치"
  }}
]

규칙:
- Project/Version/Component/Component_Version/Vulnerability 는 입력값을 그대로 복사해 주세요.
- Description: BDSA 취약점은 BD_Description을 주요 출처로 사용하고, CVE 취약점은 NVD_Description을 주요 출처로 사용하되 BD_Description이 있으면 함께 반영하여 한국어로 작성해 주세요.
- ShortTermRemediation: BD_ShortTerm_Version을 최우선으로 반영하여 "{{Component}} {{BD_ShortTerm_Version}}" 형식으로만 작성해 주세요. BD_ShortTerm_Version이 "not available at this time"인 경우 "현재 제공되지 않습니다"로만 작성해 주세요.
- LongTermRemediation: BD_LongTerm_Version을 최우선으로 반영하여 "{{Component}} {{BD_LongTerm_Version}}" 형식으로만 작성해 주세요. BD_LongTerm_Version이 "not available at this time"인 경우 "현재 제공되지 않습니다"로만 작성해 주세요.
- Workaround: BD_Workaround를 기반으로 네트워크 차단, 설정 변경, 기능 비활성화, 접근 제어 등 임시 또는 보완적 보호 조치를 더 상세하고 정확하게 한국어로 작성해 주세요. BD_Workaround가 없더라도 항상 작성해 주세요.

입력 취약점 목록:
{joined}
""".strip()


def explain_vulnerabilities_structured(
    critical_list: List[Dict],
    auth_instance,
    model: str = "claude-sonnet-4-6",
) -> List[Dict]:
    """NVD 및 BlackDuck Advisory 정보로 보강 후 Claude 분석 결과를 구조화된 리스트로 반환."""
    if not critical_list:
        return []

    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        raise RuntimeError("ANTHROPIC_API_KEY 환경 변수가 설정되어 있지 않습니다.")

    print("NVD에서 CVE 정보를 조회 중...")
    enriched_list = enrich_with_nvd(critical_list)

    print("BlackDuck Advisory에서 취약점 정보를 조회 중...")
    enriched_list = enrich_with_blackduck(auth_instance, enriched_list)

    client = anthropic.Anthropic(api_key=api_key)
    prompt = _build_prompt(enriched_list)

    message = client.messages.create(
        model=model,
        max_tokens=8192,
        messages=[{"role": "user", "content": prompt}],
    )

    raw = (message.content[0].text or "").strip()
    parsed = json.loads(raw)

    # Claude 응답에 없는 원본 필드 복원
    for original, enriched, result in zip(critical_list, enriched_list, parsed):
        result["Last_Scanned"] = original.get("Last_Scanned") or ""
        result["Severity"] = original.get("Severity", "")
        # CVSS는 NVD 값 우선, 없으면 BlackDuck Advisory 값으로 fallback
        result["CVSS_Score"] = (
            enriched.get("nvd", {}).get("cvss_score")
            or enriched.get("blackduck", {}).get("cvss_score")
            or original.get("CVSS_Score", "")
        )
        result["Workaround"] = result.get("Workaround", "")

    return parsed


def format_as_markdown_table(structured_list: List[Dict]) -> str:
    """구조화된 결과를 마크다운 테이블 문자열로 변환."""
    header = "| Project | Version | Component | Component_Version | Vulnerability | Description | Short-term Remediation | Long-term Remediation |"
    separator = "|---|---|---|---|---|---|---|---|"

    rows = []
    for item in structured_list:
        def esc(v):
            return str(v or "").replace("|", "\\|")

        rows.append(
            f"| {esc(item.get('Project'))} "
            f"| {esc(item.get('Version'))} "
            f"| {esc(item.get('Component'))} "
            f"| {esc(item.get('Component_Version'))} "
            f"| {esc(item.get('Vulnerability'))} "
            f"| {esc(item.get('Description'))} "
            f"| {esc(item.get('ShortTermRemediation'))} "
            f"| {esc(item.get('LongTermRemediation'))} |"
        )

    return "\n".join([header, separator] + rows)
