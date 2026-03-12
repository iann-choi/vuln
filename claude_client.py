import os
import json
from typing import Dict, List

import anthropic

from nvd_client import enrich_with_nvd


def _build_prompt(enriched_list: List[Dict]) -> str:
    lines = []
    for idx, item in enumerate(enriched_list, start=1):
        nvd = item.get("nvd") or {}
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
        cvss = nvd.get("cvss_score")
        cvss_str = f"CVSS={cvss}" if cvss else "CVSS=N/A"
        nvd_desc = nvd.get("description", "NVD 설명 없음")

        lines.append(
            f"{idx}. "
            f"Project={item.get('Project')}, "
            f"Version={item.get('Version')}, "
            f"Component={item.get('Component')}, "
            f"Component_Version={item.get('Component_Version')}, "
            f"Vulnerability={item.get('Vulnerability')}, "
            f"{cvss_str}, "
            f"NVD_Description={nvd_desc}, "
            f"Affected_Versions={version_info}"
        )

    joined = "\n".join(lines)

    return f"""
너는 소프트웨어 보안 전문가이다.

아래는 BlackDuck SCA 결과에서 나온 Critical 취약 컴포넌트 목록이다.
NVD에서 가져온 취약점 설명과 영향받는 버전 범위 정보가 함께 제공된다.

반드시 아래 형식의 **JSON 배열만** 반환해 주세요. (마크다운 코드블록, 설명, 머리말 포함 금지)

[
  {{
    "Project": "...",
    "Version": "...",
    "Component": "...",
    "Component_Version": "...",
    "Vulnerability": "...",
    "Description": "한국어 설명",
    "ShortTermRemediation": "한국어 단기 조치 (구체적 버전 포함)",
    "LongTermRemediation": "한국어 장기 조치"
  }}
]

규칙:
- Project/Version/Component/Component_Version/Vulnerability 는 입력값을 그대로 복사해 주세요.
- Description: NVD 설명 기반으로 취약점 핵심 내용을 한국어로 간결하게 작성해 주세요.
- ShortTermRemediation: NVD Affected_Versions의 fix 버전을 참고하여 즉시 적용 가능한 패치 버전을 명시해 주세요. 버전 정보가 있으면 반드시 구체적인 버전 번호를 포함해 주세요.
- LongTermRemediation: 근본적인 해결 방향을 작성해 주세요. (예: 최신 메이저 버전으로 마이그레이션하세요, 대체 라이브러리 도입을 검토해 보세요 등)
- NVD 버전 정보가 없는 경우 ShortTermRemediation은 "최신 안정 버전으로 업그레이드하시기 바랍니다"로 작성해 주세요.

입력 취약점 목록:
{joined}
""".strip()


def explain_vulnerabilities_structured(
    critical_list: List[Dict],
    model: str = "claude-sonnet-4-6",
) -> List[Dict]:
    """NVD 정보로 보강 후 Claude 분석 결과를 구조화된 리스트로 반환."""
    if not critical_list:
        return []

    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        raise RuntimeError("ANTHROPIC_API_KEY 환경 변수가 설정되어 있지 않습니다.")

    print("NVD에서 CVE 정보를 조회 중...")
    enriched_list = enrich_with_nvd(critical_list)

    client = anthropic.Anthropic(api_key=api_key)
    prompt = _build_prompt(enriched_list)

    message = client.messages.create(
        model=model,
        max_tokens=4096,
        messages=[{"role": "user", "content": prompt}],
    )

    raw = (message.content[0].text or "").strip()
    return json.loads(raw)


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
