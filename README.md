# PathLens

PathLens는 공개 인증서와 DNS 정보로 도메인에서 AWS 서비스까지 이어지는 단서를 정리하는 오픈소스 프로토타입입니다. 판단 결과와 함께 근거를 제공하며 CLI와 MCP에서 같은 분석 기능을 사용할 수 있습니다.

## 현재 범위

- crt.sh 인증서 기록에서 입력 도메인 아래의 이름을 찾고 공개 DNS 리졸버에 CNAME, A, AAAA 레코드를 질의합니다.
- AWS의 공개 IP 대역과 AWS 서비스 도메인 특징을 대조합니다.
- YAML 규칙 세 개로 알려진 서비스 연결, NXDOMAIN 연결, AWS 인프라 단서를 구분합니다.
- JSON 보고서, Markdown 보고서, 원본 관찰 스냅샷을 출력합니다.
- MCP stdio 도구로 동일한 분석을 제공합니다.

자산 소유 여부, 버킷 존재 여부, 탈취 가능성 또는 실제 취약점은 확인하지 않습니다. 인증서 기록은 오래되었을 수 있습니다. AWS IP 대역은 일부 주소를 포함하지 않으며 해당 주소의 고객이나 소유자를 알려주지 않습니다. 서비스 목록은 예시이며 완전하거나 최신 상태라고 보장하지 않습니다. **결과는 사람이 확인할 후보입니다.**

## 설치

Python 3.11 이상이 필요합니다.

```bash
git clone https://github.com/ziyye3/PathLens.git
cd PathLens
python -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
```

Windows PowerShell에서는 활성화 명령이 `.venv\Scripts\Activate.ps1`입니다.

## 네트워크 없이 예제 실행

예제의 도메인, IP 범위, 결과는 모두 가상 데이터입니다. 실제 AWS 소유나 취약점을 나타내지 않습니다.

```bash
pathlens scan example.com --snapshot examples/sample.json --output pathlens-output/example
```

생성 파일:

- `report.json`: 분석 결과와 근거
- `report.md`: 읽기 쉬운 결과
- `observations.json`: 분석에 사용한 원본 관찰값. 공개 DNS와 인증서 데이터가 포함됩니다.

같은 디렉터리에 위 파일이 이미 있으면 덮어쓰지 않습니다. 다시 실행할 때는 다른 `--output` 경로를 사용하세요.

## 공개 정보 조회

소유하거나 명시적으로 허가받은 도메인에서만 실행하세요.

```bash
pathlens scan example.com --authorized --max-assets 50 --output pathlens-output/live
```

실행 시 입력 도메인은 `crt.sh`에, 발견된 이름은 Cloudflare 공개 DNS 리졸버 `1.1.1.1`에 전송됩니다. DNS 질의는 재귀 리졸버를 거쳐 해당 도메인의 권한 DNS 서버에 전달될 수 있습니다. AWS IP 대역 파일은 `ip-ranges.amazonaws.com`에서 받습니다. PathLens는 발견된 웹서비스에 HTTP 요청을 보내거나 인증을 시도하지 않습니다. 사용자 확인은 법적 소유권 검증을 대신하지 않습니다.

crt.sh 수집이 실패하면 실행을 중단합니다. AWS 대역 수집이 실패하거나 DNS가 응답하지 않으면 경고를 표시하고 결과를 제한된 근거로만 해석합니다. 자산 수는 기본 100개, 최대 200개로 제한합니다. 공개 서비스의 이용 정책과 조회 빈도를 지켜주세요.

## MCP 연결

MCP 서버는 기본적으로 stdio를 사용합니다. 로그와 프로토콜 메시지가 섞이지 않도록 서버를 별도 프로세스로 실행합니다.

```json
{
  "mcpServers": {
    "pathlens": {
      "command": "/absolute/path/to/PathLens/.venv/bin/pathlens-mcp",
      "args": []
    }
  }
}
```

도구는 두 개입니다.

- `analyze_snapshot`: JSON 스냅샷을 네트워크 없이 분석합니다.
- `scan_domain`: 도메인과 `authorized: true`를 전달한 경우 공개 정보 조회를 수행합니다. MCP 호스트에서는 조회 전에 사용자가 도메인과 외부 전송을 확인해야 합니다.

## 규칙과 위험 목록

`src/pathlens/data/rules.yaml`에 세 규칙이 있고 `services.yaml`에 대조할 서비스가 있습니다. `--rules`로 YAML 규칙 파일을 지정할 수 있습니다. 실행 가능한 코드나 임의의 식은 지원하지 않습니다.

1. 알려진 서비스 CNAME의 대상이 NXDOMAIN이면 높은 우선순위의 확인 후보로 표시합니다.
2. S3 또는 Elastic Beanstalk처럼 검토가 필요한 서비스와 연결되면 수동 확인 후보로 표시합니다.
3. AWS 서비스 이름이나 AWS 공개 IP 대역과 맞으면 인프라 단서를 표시합니다.

여러 규칙이 일치하면 가장 높은 우선순위(`high > medium > low > info`)를 자산에 표시하고,
적용된 규칙과 근거는 모두 보존합니다. 일치하는 규칙이 없으면 `unknown`이며 안전 판정이 아닙니다.

NXDOMAIN이나 서비스 목록 일치만으로 탈취 가능 여부를 확정할 수 없습니다. CISA KEV는 CVE 목록이며 이 서비스 목록과 다른 데이터입니다. 목록의 출처와 현재 한계는 `services.yaml`과 보고서에서 확인할 수 있습니다.

## 스냅샷 입력

`examples/sample.json`은 crt.sh의 `name_value`, DNS 관찰값, AWS IP 대역 JSON 구조를 포함합니다. 입력 도메인과 스냅샷의 `domain`은 일치해야 합니다. DNS 응답 상태는 `answer`, `nxdomain`, `nodata`, `timeout`, `error` 중 하나로 구분합니다. 와일드카드 인증서는 실제 호스트 이름으로 간주하지 않습니다.

## 검증

```bash
pytest
ruff check .
```

가상 데이터 기반 테스트는 실제 서비스, 실제 탈취 가능성, 또는 전체 인터넷에서의 정확도를 보장하지 않습니다. 실제 소유한 테스트 도메인으로 별도 검증이 필요합니다.
테스트 중 하나는 DNS 패킷 처리 확인을 위해 `127.0.0.1`에 임시 UDP 서버를 열고 종료합니다.
외부 도메인이나 발견된 웹서비스에는 테스트 요청을 보내지 않습니다.

## 참고자료

- [AWS IP address ranges](https://docs.aws.amazon.com/vpc/latest/userguide/aws-ip-ranges.html)
- [AWS S3 virtual hosting and DNS aliases](https://docs.aws.amazon.com/AmazonS3/latest/userguide/VirtualHosting.html)
- [Can I Take Over XYZ?](https://github.com/EdOverflow/can-i-take-over-xyz)
- [MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk)

## 라이선스

MIT. 자세한 내용은 [LICENSE](LICENSE)를 확인하세요.

