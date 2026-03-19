import os
import json
from typing import Dict, List

import anthropic

from nvd_client import enrich_with_nvd
from blackduck_advisory_client import enrich_with_blackduck
from osv_client import enrich_with_osv
from cisa_client import enrich_with_cisa
from github_advisory_client import enrich_with_github


def _build_prompt(enriched_list: List[Dict]) -> str:
    lines = []
    for idx, item in enumerate(enriched_list, start=1):
        nvd = item.get("nvd") or {}
        bd = item.get("blackduck") or {}
        osv = item.get("osv") or {}
        cisa = item.get("cisa") or {}
        gh = item.get("github") or {}
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
        cisa_exploited = "예" if cisa.get("actively_exploited") else "아니오"
        cisa_ransomware = cisa.get("ransomware_use", "Unknown")
        cisa_due_date = cisa.get("due_date", "")
        gh_severity = gh.get("severity", "")
        gh_fix_versions = ", ".join(gh.get("fix_versions", [])) or "없음"
        gh_affected = "; ".join(
            f"{p['package']} {p['vulnerable_range']} → fix: {p['first_patched_version'] or '미정'}"
            for p in gh.get("affected_packages", [])
        ) or "없음"

        lines.append(
            f"{idx}. "
            f"Project={item.get('Project')}, "
            f"Version={item.get('Version')}, "
            f"Component={item.get('Component')}, "
            f"Component_Version={item.get('Component_Version')}, "
            f"Vulnerability={item.get('Vulnerability')}, "
            f"{cvss_str}, "
            f"CISA_KEV_Exploited={cisa_exploited}, "
            f"CISA_Ransomware={cisa_ransomware}, "
            f"CISA_DueDate={cisa_due_date or '없음'}, "
            f"NVD_Description={nvd_desc or '없음'}, "
            f"BD_Description={bd_desc or '없음'}, "
            f"BD_ShortTerm_Version={bd_short or 'not available at this time'}, "
            f"BD_LongTerm_Version={bd_long or 'not available at this time'}, "
            f"BD_Workaround={bd_workaround or '없음'}, "
            f"Affected_Versions={version_info}, "
            f"OSV_Summary={osv_summary or '없음'}, "
            f"OSV_Details={osv_details or '없음'}, "
            f"OSV_Fix_Versions={osv_fix_versions}, "
            f"OSV_Aliases={osv_aliases}, "
            f"GH_Severity={gh_severity or '없음'}, "
            f"GH_Fix_Versions={gh_fix_versions}, "
            f"GH_Affected_Packages={gh_affected}"
        )

    joined = "\n".join(lines)

    return f"""
너는 10년 이상 경력의 소프트웨어 공급망 보안 전문가이다.

아래는 BlackDuck SCA 결과에서 나온 Critical 취약 컴포넌트 목록이다.
NVD, BlackDuck Security Advisor, OSV(Open Source Vulnerabilities), CISA KEV(Known Exploited Vulnerabilities), GitHub Advisory DB 다섯 곳에서 가져온 원시 데이터가 함께 제공된다.
이 데이터는 참고 자료일 뿐이며, 너는 이를 맹신하지 않고 다섯 소스를 교차 검토하여 전문가 시각으로 판단해야 한다.
- CISA_KEV_Exploited=예 인 경우, 미국 정부가 실제 공격에 악용됨을 공식 확인한 취약점이다. 조치 긴급도를 최우선으로 판단하라.
- CISA_Ransomware=Known 인 경우, 랜섬웨어 캠페인에 활발히 사용 중임을 의미한다. Workaround에 즉각 격리/차단 조치를 반드시 포함하라.

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
- BDSA 취약점처럼 NVD에 정보가 없는 경우 Open Source Vulnerabilities(OSV)와 BlackDuck 데이터를 주요 출처로 활용하라.
- 단순 번역이나 복사가 아닌, 실제 공격 시나리오와 영향 범위를 포함하여 개발자가 위험성을 직관적으로 이해할 수 있도록 한국어로 작성하라.
- 해당 취약점이 어떤 방식으로 악용될 수 있는지, 어떤 시스템/환경이 위험에 노출되는지를 명확히 서술하라.

[ShortTermRemediation]
- BD_ShortTerm_Version, OSV_Fix_Versions, GH_Fix_Versions를 함께 참고하여 교차 검증하라.
- GH_Fix_Versions는 패키지 생태계 기준으로 가장 정확한 수정 버전을 제공하므로 우선 신뢰하라.
- 여러 소스가 일치하면 해당 버전을 신뢰하고 "{{Component}} {{버전}}" 형식으로 작성.
- 소스 간 불일치 시 GH_Fix_Versions → OSV_Fix_Versions → BD_ShortTerm_Version 순으로 우선 반영하고 너의 지식으로 최종 판단하여 작성.
- 모든 소스에 정보가 없으면 너의 지식으로 적절한 버전을 제시하고, 판단 불가 시 "현재 제공되지 않습니다"로 작성.

[LongTermRemediation]
- BD_LongTerm_Version, OSV_Fix_Versions, GH_Fix_Versions, GH_Affected_Packages를 함께 참고하여 교차 검증하라.
- GH_Affected_Packages의 first_patched_version을 패키지별 장기 수정 기준으로 활용하라.
- 여러 소스가 일치하면 해당 버전을 신뢰하고 "{{Component}} {{버전}}" 형식으로 작성.
- 소스 간 불일치 시 GH_Fix_Versions → Open Source Vulnerabilities(OSV) 데이터를 우선 반영하고 너의 지식으로 가장 안정적인 장기 수정 버전을 최종 판단하여 작성.
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


def _sanitize_json(text: str) -> str:
    """JSON 문자열 내 유효하지 않은 백슬래시 이스케이프를 수정."""
    import re

    result = []
    i = 0
    while i < len(text):
        if text[i] == '\\' and i + 1 < len(text):
            next_ch = text[i + 1]
            if next_ch in ('"', '\\', '/', 'b', 'f', 'n', 'r', 't'):
                # 유효한 단순 이스케이프
                result.append(text[i:i+2])
                i += 2
            elif next_ch == 'u':
                # \uXXXX 형식인지 확인 (4자리 16진수)
                hex_part = text[i+2:i+6]
                if len(hex_part) == 4 and all(c in '0123456789abcdefABCDEF' for c in hex_part):
                    result.append(text[i:i+6])
                    i += 6
                else:
                    # \u 뒤가 올바른 hex가 아님 → 이스케이프
                    result.append('\\\\')
                    i += 1
            else:
                # 그 외 유효하지 않은 이스케이프 → 이스케이프
                result.append('\\\\')
                i += 1
        else:
            result.append(text[i])
            i += 1

    return ''.join(result)


def _parse_claude_response(raw: str) -> List[Dict]:
    """Claude 응답 문자열을 JSON으로 파싱. 실패 시 빈 리스트 반환."""
    import re

    text = raw.strip()
    # 마크다운 코드블록 제거
    text = re.sub(r'^```(?:json)?\s*', '', text)
    text = re.sub(r'\s*```$', '', text)
    text = text.strip()

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        sanitized = _sanitize_json(text)
        try:
            return json.loads(sanitized)
        except json.JSONDecodeError as e:
            print(f"  [Claude] JSON 파싱 실패: {e}")
            return []


def _call_claude_batch(client, model: str, batch: List[Dict]) -> List[Dict]:
    """단일 배치에 대해 Claude API를 호출하고 파싱된 결과를 반환."""
    prompt = _build_prompt(batch)
    message = client.messages.create(
        model=model,
        max_tokens=8192,
        messages=[{"role": "user", "content": prompt}],
    )
    raw = (message.content[0].text or "").strip()
    return _parse_claude_response(raw)


def _restore_fields(results: List[Dict], originals: List[Dict], enriched: List[Dict]) -> None:
    """Claude 응답에 없는 원본 필드를 복원."""
    for original, enriched_item, result in zip(originals, enriched, results):
        result["Last_Scanned"] = original.get("Last_Scanned") or ""
        result["Severity"] = original.get("Severity", "")
        result["CVSS_Score"] = (
            original.get("CVSS_Score")
            or enriched_item.get("nvd", {}).get("cvss_score")
            or enriched_item.get("blackduck", {}).get("cvss_score")
            or ""
        )
        result["Workaround"] = result.get("Workaround", "")
        main_id = original.get("Vulnerability", "")
        osv_aliases = enriched_item.get("osv", {}).get("aliases", [])
        seen = {main_id}
        vuln_ids = [main_id]
        for alias in osv_aliases:
            if alias not in seen:
                seen.add(alias)
                vuln_ids.append(alias)
        result["VulnIDs"] = vuln_ids


def explain_vulnerabilities_structured(
    critical_list: List[Dict],
    auth_instance,
    model: str = "claude-sonnet-4-6",
    batch_size: int = 5,
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

    print("Open Source Vulnerabilities(OSV)에서 취약점 정보를 조회 중...")
    enriched_list = enrich_with_osv(enriched_list)

    print("CISA KEV 등재 여부 확인 중...")
    enriched_list = enrich_with_cisa(enriched_list)

    print("GitHub Advisory DB에서 취약점 정보를 조회 중...")
    enriched_list = enrich_with_github(enriched_list)

    client = anthropic.Anthropic(api_key=api_key)
    all_results = []

    total = len(enriched_list)
    for start in range(0, total, batch_size):
        end = min(start + batch_size, total)
        batch = enriched_list[start:end]
        print(f"  [Claude] {start + 1}~{end}/{total} 분석 중...")

        parsed = _call_claude_batch(client, model, batch)

        if len(parsed) != len(batch):
            print(f"  [Claude] 경고: 배치 {start + 1}~{end} 결과 수 불일치 ({len(parsed)}/{len(batch)}), 항목별 개별 재시도...")
            parsed = []
            successful_originals = []
            successful_enriched = []
            for i, item in enumerate(batch):
                global_idx = start + i
                vuln_id = critical_list[global_idx].get("Vulnerability", f"#{global_idx + 1}")
                print(f"  [Claude] 개별 재시도: {vuln_id} ({i + 1}/{len(batch)})")
                single = _call_claude_batch(client, model, [item])
                if len(single) == 1:
                    parsed.append(single[0])
                    successful_originals.append(critical_list[global_idx])
                    successful_enriched.append(item)
                else:
                    print(f"  [Claude] 경고: {vuln_id} 개별 분석 실패, 건너뜀")

            if not parsed:
                print(f"  [Claude] 경고: 배치 {start + 1}~{end} 전체 실패, 건너뜀")
                continue

            _restore_fields(parsed, successful_originals, successful_enriched)
            all_results.extend(parsed)
            continue

        _restore_fields(parsed, critical_list[start:end], batch)
        all_results.extend(parsed)

    return all_results


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
