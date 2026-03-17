import os
import json
from typing import Dict, List

import anthropic

from nvd_client import enrich_with_nvd
from blackduck_advisory_client import enrich_with_blackduck
from osv_client import enrich_with_osv


def _build_prompt(enriched_list: List[Dict]) -> str:
    lines = []
    for idx, item in enumerate(enriched_list, start=1):
        nvd = item.get("nvd") or {}
        bd = item.get("blackduck") or {}
        osv = item.get("osv") or {}
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
        bd_workaround = bd.get("workaround", "")
        bd_short = bd.get("short_term_version", "")
        bd_long = bd.get("long_term_version", "")
        osv_summary = osv.get("summary", "")
        osv_details = osv.get("details", "")
        osv_fix_versions = ", ".join(osv.get("fix_versions", [])) or "없음"
        osv_aliases = ", ".join(osv.get("aliases", [])) or "없음"

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
            f"Affected_Versions={version_info}, "
            f"OSV_Summary={osv_summary or '없음'}, "
            f"OSV_Details={osv_details or '없음'}, "
            f"OSV_Fix_Versions={osv_fix_versions}, "
            f"OSV_Aliases={osv_aliases}"
        )

    joined = "\n".join(lines)

    return f"""
너는 10년 이상 경력의 소프트웨어 공급망 보안 전문가이다.

아래는 BlackDuck SCA 결과에서 나온 Critical 취약 컴포넌트 목록이다.
NVD, BlackDuck Security Advisor, OSV(Open Source Vulnerabilities) 세 곳에서 가져온 원시 데이터가 함께 제공된다.
이 데이터는 참고 자료일 뿐이며, 너는 이를 맹신하지 않고 세 소스를 교차 검토하여 전문가 시각으로 판단해야 한다.

반드시 아래 형식의 **JSON 배열만** 반환해 주세요. (마크다운 코드블록, 설명, 머리말 포함 금지)

[
  {{
    "Project": "...",
    "Version": "...",
    "Component": "...",
    "Component_Version": "...",
    "Vulnerability": "...",
    "Description": "한국어 설명",
    "ShortTermRemediation": "단기 조치 버전",
    "LongTermRemediation": "장기 조치 버전",
    "Workaround": "한국어 임시 보호 조치"
  }}
]

각 필드별 작성 기준:

[Project / Version / Component / Component_Version / Vulnerability]
- 입력값을 그대로 복사해 주세요.

[Description]
- NVD_Description, BD_Description, OSV_Summary, OSV_Details를 모두 교차 검토하고 너의 보안 지식을 더해 종합하라.
- BDSA 취약점처럼 NVD에 정보가 없는 경우 OSV와 BD 데이터를 주요 출처로 활용하라.
- 단순 번역이나 복사가 아닌, 실제 공격 시나리오와 영향 범위를 포함하여 개발자가 위험성을 직관적으로 이해할 수 있도록 한국어로 작성하라.
- 해당 취약점이 어떤 방식으로 악용될 수 있는지, 어떤 시스템/환경이 위험에 노출되는지를 명확히 서술하라.

[ShortTermRemediation]
- BD_ShortTerm_Version과 OSV_Fix_Versions를 함께 참고하여 교차 검증하라.
- 두 소스가 일치하면 해당 버전을 신뢰하고 "{{Component}} {{버전}}" 형식으로 작성.
- 두 소스가 다르거나 BD 버전이 존재하지 않는다고 판단되면, OSV_Fix_Versions를 우선 반영하고 너의 지식으로 최종 판단하여 작성.
- 모든 소스에 정보가 없으면 너의 지식으로 적절한 버전을 제시하고, 판단 불가 시 "현재 제공되지 않습니다"로 작성.

[LongTermRemediation]
- BD_LongTerm_Version과 OSV_Fix_Versions, OSV_Aliases(관련 CVE/GHSA)를 함께 참고하여 교차 검증하라.
- 두 소스가 일치하면 해당 버전을 신뢰하고 "{{Component}} {{버전}}" 형식으로 작성.
- 두 소스가 다르거나 BD 버전이 존재하지 않는다고 판단되면, OSV 데이터를 우선 반영하고 너의 지식으로 가장 안정적인 장기 수정 버전을 최종 판단하여 작성.
- 모든 소스에 정보가 없으면 너의 지식으로 적절한 버전을 제시하고, 판단 불가 시 "현재 제공되지 않습니다"로 작성.

[Workaround]
- BD_Workaround와 OSV_Details의 완화 조치 내용을 함께 참고하되, 단순 복사가 아닌 전문가 시각에서 실효성을 검토하여 보완하라.
- 취약점의 공격 벡터(네트워크, 로컬, 의존성 등)를 고려하여, 실제로 적용 가능한 조치를 구체적으로 작성하라.
- 예: 네트워크 차단, 환경변수·시크릿 즉시 교체, 의존성 제거, 기능 비활성화, 접근 제어 강화, 모니터링 강화 등.
- 어떤 소스에도 정보가 없어도 너의 지식으로 반드시 실질적인 조치를 작성하라.
- 공급망 공격(멀웨어 패키지)의 경우, 단순 버전 업그레이드가 아닌 환경 전체 침해 가정 하의 대응 절차를 포함하라.

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

    print("OSV에서 취약점 정보를 조회 중...")
    enriched_list = enrich_with_osv(enriched_list)

    client = anthropic.Anthropic(api_key=api_key)
    prompt = _build_prompt(enriched_list)

    message = client.messages.create(
        model=model,
        max_tokens=8192,
        messages=[{"role": "user", "content": prompt}],
    )

    raw = (message.content[0].text or "").strip()
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        # 유효하지 않은 백슬래시 이스케이프 제거 후 재시도
        import re
        sanitized = re.sub(r'\\(?!["\\/bfnrtu])', r'\\\\', raw)
        parsed = json.loads(sanitized)

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
        # 관련 취약점 ID 목록 (메인 ID + OSV aliases, 중복 제거)
        main_id = original.get("Vulnerability", "")
        osv_aliases = enriched.get("osv", {}).get("aliases", [])
        seen = {main_id}
        vuln_ids = [main_id]
        for alias in osv_aliases:
            if alias not in seen:
                seen.add(alias)
                vuln_ids.append(alias)
        result["VulnIDs"] = vuln_ids

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
