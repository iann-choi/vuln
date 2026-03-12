import os
from typing import Dict, List

import anthropic


def _build_prompt_markdown_table(critical_list: List[Dict]) -> str:
    lines = []
    for idx, item in enumerate(critical_list, start=1):
        lines.append(
            f"{idx}. "
            f"Project={item.get('Project')}, "
            f"Version={item.get('Version')}, "
            f"Component={item.get('Component')}, "
            f"Component_Version={item.get('Component_Version')}, "
            f"Vulnerability={item.get('Vulnerability')}"
        )

    joined = "\n".join(lines)

    return f"""
너는 소프트웨어 보안 전문가이다.

아래는 BlackDuck SCA 결과에서 나온 Critical 취약 컴포넌트 목록이다.
각 항목에 대해 취약점 설명과 조치 방법을 작성하라.

출력은 반드시 **마크다운 테이블 1개만** 반환하라. (다른 문장/설명/코드블록/머리말 금지)
테이블은 아래 컬럼을 정확히 포함해야 한다:

| Project | Version | Component | Component_Version | Vulnerability | Description | Remediation |

규칙:
- 입력으로 받은 Project/Version/Component/Component_Version/Vulnerability 값은 그대로 복사해 넣어라.
- Description/Remediation은 한국어로 간결하게 작성하라.
- 테이블 셀 안에서는 줄바꿈을 피하고, 필요한 경우 문장 구분은 '; '로 하라.
- 테이블에서 '|' 문자는 이스케이프('\\|') 처리하라.

입력 취약점 목록:
{joined}
""".strip()


def explain_vulnerabilities_with_claude_markdown_table(
    critical_list: List[Dict],
    model: str = "claude-sonnet-4-6",
) -> str:
    """
    scanner.py 에서 받아온 critical 취약 컴포넌트 리스트를 Claude에 보내서
    설명 및 조치 방법이 포함된 '마크다운 테이블 문자열'로 반환.
    """
    if not critical_list:
        return ""

    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        raise RuntimeError("ANTHROPIC_API_KEY 환경 변수가 설정되어 있지 않습니다.")

    client = anthropic.Anthropic(api_key=api_key)
    prompt = _build_prompt_markdown_table(critical_list)

    message = client.messages.create(
        model=model,
        max_tokens=2048,
        messages=[
            {"role": "user", "content": prompt}
        ],
    )

    return (message.content[0].text or "").strip()
