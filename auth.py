import requests
import urllib3

# SSL 경고 무시 (사설 인증서 사용 시 필수)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class BlackDuckAuth:
    def __init__(self, base_url, api_token):
        self.base_url = base_url.rstrip('/')
        self.api_token = api_token
        self.session = requests.Session()
        self.session.verify = False  # SSL 검증 무시 설정 유지

    def authenticate(self):
        """API 토큰으로 Bearer 토큰을 받아 세션에 등록"""
        auth_url = f"{self.base_url}/api/tokens/authenticate"
        headers = {
            "Authorization": f"token {self.api_token}",
            "Accept": "application/vnd.blackducksoftware.user-4+json"
        }
        
        try:
            response = self.session.post(auth_url, headers=headers)
            if response.status_code == 200:
                token = response.json().get("bearerToken")
                # 이후 모든 요청에 사용할 공통 헤더 설정
                self.session.headers.update({"Authorization": f"Bearer {token}"})
                return True
            else:
                print(f"인증 실패: 상태 코드 {response.status_code}")
                return False
        except Exception as e:
            print(f"인증 중 에러 발생: {e}")
            return False
