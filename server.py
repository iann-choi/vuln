import hashlib
import hmac
import json
import os
import time

from fastapi import FastAPI, Form, HTTPException, Request
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError

app = FastAPI()

STORE_PATH = os.path.join(os.path.dirname(__file__), ".item_store.json")


def _load_item_store() -> dict:
    if os.path.exists(STORE_PATH):
        with open(STORE_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}


def _verify_slack_signature(request_body: bytes, timestamp: str, signature: str) -> bool:
    """Slack 요청의 서명을 검증하여 위변조를 방지."""
    signing_secret = os.getenv("SLACK_SIGNING_SECRET", "")

    # 5분 이상 지난 요청은 거부 (replay attack 방지)
    if abs(time.time() - int(timestamp)) > 60 * 5:
        return False

    base_string = f"v0:{timestamp}:{request_body.decode('utf-8')}"
    expected = "v0=" + hmac.new(
        signing_secret.encode(),
        base_string.encode(),
        hashlib.sha256,
    ).hexdigest()

    return hmac.compare_digest(expected, signature)


def _update_message_status(
    client: WebClient,
    channel_id: str,
    message_ts: str,
    item: dict,
    status: str,  # "confirmed" | "ignored"
) -> None:
    """버튼 클릭 후 해당 메시지의 액션 버튼을 상태 표시로 교체."""
    vuln = item.get("Vulnerability", "")
    component = item.get("Component", "")

    if status == "confirmed":
        status_block = {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"✅ *확인 완료* — 담당자가 검토하였습니다.",
            },
        }
    else:
        status_block = {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "❌ *무시됨* — 이 취약점은 무시 처리되었습니다.",
            },
        }

    updated_blocks = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": f"🔴 {vuln}"},
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Project:*\n{item.get('Project')} `{item.get('Version')}`"},
                {"type": "mrkdwn", "text": f"*Component:*\n{component} `{item.get('Component_Version')}`"},
            ],
        },
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"*📋 설명*\n{item.get('Description', '')}"},
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*⚡ Short-term*\n{item.get('ShortTermRemediation', '')}"},
                {"type": "mrkdwn", "text": f"*🔭 Long-term*\n{item.get('LongTermRemediation', '')}"},
            ],
        },
        status_block,
        {"type": "divider"},
    ]

    client.chat_update(
        channel=channel_id,
        ts=message_ts,
        blocks=updated_blocks,
        text=f"[{vuln}] {component} — {status}",
    )


@app.post("/slack/interactions")
async def handle_interaction(request: Request, payload: str = Form(...)):
    # 1. 서명 검증
    body = await request.body()
    timestamp = request.headers.get("X-Slack-Request-Timestamp", "")
    signature = request.headers.get("X-Slack-Signature", "")

    if not _verify_slack_signature(body, timestamp, signature):
        raise HTTPException(status_code=403, detail="Invalid Slack signature")

    # 2. 페이로드 파싱
    data = json.loads(payload)
    action_list = data.get("actions", [])
    if not action_list:
        return {"ok": True}

    action = action_list[0]
    action_id = action.get("action_id")
    item_id = action.get("value")
    channel_id = data.get("channel", {}).get("id")
    message_ts = data.get("message", {}).get("ts")

    if action_id not in ("confirm_component", "ignore_component"):
        return {"ok": True}

    # 3. item_store에서 컴포넌트 데이터 조회
    item_store = _load_item_store()
    item = item_store.get(item_id)
    if not item:
        print(f"[Server] item_id={item_id} 를 store에서 찾을 수 없음")
        return {"ok": True}

    # 4. 메시지 업데이트
    token = os.getenv("SLACK_BOT_TOKEN", "")
    client = WebClient(token=token)
    status = "confirmed" if action_id == "confirm_component" else "ignored"

    try:
        _update_message_status(client, channel_id, message_ts, item, status)
        print(f"[Server] {item_id} → {status}")
    except SlackApiError as e:
        print(f"[Server] 메시지 업데이트 실패: {e.response['error']}")

    return {"ok": True}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server:app", host="0.0.0.0", port=8000, reload=True)
