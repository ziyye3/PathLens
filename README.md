# PathLens

PathLens는 공개 인증서와 DNS 정보로 도메인에서 AWS 서비스까지 이어지는 단서를 정리하는 오픈소스 프로토타입입니다. 판단 결과와 함께 근거를 제공하며 CLI와 MCP에서 같은 분석 기능을 사용할 수 있습니다.

## 현재 범위

- crt.sh 인증서 기록에서 입력 도메인 아래의 이름을 찾고 공개 DNS 리졸버에 CNAME, A, AAAA 레코드를 질의합니다.
- AWS의 공개 IP 대역과 AWS 서비스 도메인 특징을 대조합니다.
- YAML 규칙 세 개로 알려진 서비스 연결, NXDOMAIN 연결, AWS 인프라 단서를 구분합니다.
- AWS 문서에 근거한 S3·Elastic Beanstalk 위험 맥락을 해당 관찰과 연결합니다.
- 선택적으로 로컬 TI 피드 또는 Feodo Tracker 공개 IP 목록과 정확히 일치하는 값을 표시합니다.
- JSON 보고서, Markdown 보고서, 원본 관찰 스냅샷을 출력합니다.
- MCP stdio 도구로 동일한 분석을 제공합니다.
- 서버 없이 브라우저에서 `report.json`을 확인하는 로컬 대시보드를 제공합니다.

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

## 로컬 대시보드

```bash
pathlens dashboard
```

기본 브라우저에서 대시보드가 열립니다. 처음 표시되는 내용은 **가상 데모**입니다. `보고서 열기`에서 위 `scan` 명령으로 만든 `report.json`을 선택하면 자산, 우선순위, DNS 경로, 규칙 근거와 TI 요약을 살펴볼 수 있습니다. 검색과 우선순위 필터를 지원합니다. `데모 보기`를 누르면 가상 화면으로 돌아갑니다.

선택한 파일은 브라우저에서만 읽으며 서버에 저장하거나 업로드하지 않습니다. 대시보드는 분석 결과를 보여주는 도구로, 화면에서 새 분석을 실행하거나 다크웹을 수집하지 않습니다. TI·STIX 일치는 침해 사실을 확정하지 않습니다. 읽을 수 있는 보고서는 현재 PathLens의 `schema_version: 1.0`, 최대 25 MiB, 최대 200개 자산으로 제한합니다. `pathlens dashboard --no-open`은 브라우저를 열지 않고 로컬 파일 주소만 출력합니다.

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

두 도구 모두 `threat_feed`, `cve_observations`, `product_observations`, `kev_catalog`, `exposure_observations`, `osv_observations`, `osv_results` 및 `stix_bundle` 인자에 아래 형식의 JSON 객체를 선택적으로 전달할 수 있습니다. `stix_indicator_ids`로 평가할 원본 지표를 선택할 수 있습니다. CVE 또는 제품 관찰값은 KEV 목록과, OSV 관찰값은 OSV 결과와 함께 제공해야 합니다. 파일 경로를 전달하거나 OSV 피드를 자동으로 내려받지 않습니다. 반환값은 자산별 분석과 각 입력의 처리 상태를 포함합니다.

## 위협 인텔리전스

PathLens는 두 종류의 정보를 구분합니다.

1. **위협 맥락**: AWS 공식 문서에서 확인한 S3·Elastic Beanstalk DNS 연결 관련 주의사항입니다. 해당 서비스의 관찰과 규칙이 맞을 때 출처와 검토일을 함께 표시합니다. 버킷이나 환경이 실제 존재하는지 확인하지 않습니다.
2. **지표 일치**: 사용자가 제공한 TI 피드의 도메인 또는 IP가 관찰된 값과 정확히 같을 때 표시합니다. 도메인은 하위 도메인으로 확장하지 않습니다. CNAME 대상과 IP는 공유 인프라일 수 있고, 일치는 침해나 공격자 귀속의 증거가 아닙니다.

피드를 제공하지 않으면 `not_supplied`로 표시합니다. 빈 피드·일치 없음은 안전 판정이 아닙니다. 각 지표는 출처, 유효 시작과 종료 시각, 관찰 근거, 일치 상태를 갖습니다. `active`는 설정된 유효 기간에 해당한다는 뜻일 뿐 현재 악성 활동을 확인했다는 뜻이 아닙니다. 만료되거나 관찰 시점 전에 유효하지 않은 지표도 그 상태를 명시하여 보여줍니다. TI 일치만으로 기존 자산 우선순위를 자동으로 높이지 않습니다.

### 가상 TI 예제

예제는 모두 가상의 지표이며 실제 위협을 의미하지 않습니다.

```bash
pathlens validate-feed examples/threat-feed.json
pathlens scan example.com --snapshot examples/sample.json \
  --threat-feed examples/threat-feed.json --output pathlens-output/ti-example
```

### 실제 공개 TI 피드 받아오기

사용자가 명령할 때만 Feodo Tracker의 추천 IP 목록을 받아 PathLens 형식으로 변환합니다. 대상 도메인은 Feodo에 전송하지 않습니다. 기존 파일은 덮어쓰지 않으므로 갱신할 때 새 파일명을 지정하세요. 기본적으로 백그라운드에서 갱신하지 않으며, 선택적인 주기 갱신은 아래에서 설명합니다.

```bash
pathlens update-feodo --output /tmp/pathlens-feodo-1.json
pathlens validate-feed /tmp/pathlens-feodo-1.json
pathlens scan YOUR-AUTHORIZED-DOMAIN --authorized \
  --threat-feed /tmp/pathlens-feodo-1.json --output pathlens-output/live-ti
```

Feodo 변환의 유효 종료 시각은 **PathLens의 수집 후 24시간 보관 기준**이며, 제공자가 보장한 위협 종료 시각이 아닙니다. 원본의 마지막 온라인 날짜와 상태를 함께 표시합니다. IP 재할당, CDN 등으로 오탐이 생길 수 있으므로 수동 확인이 필요합니다. 피드가 비어 있거나 조회가 실패할 수 있으며, 받아오기 전 [제공자의 이용 조건](https://abuse.ch/terms-of-use/)을 확인하세요. 이 목록은 AWS 전용 목록이 아닙니다.

### 자체 TI 피드

`examples/threat-feed.json`을 참고해 UTF-8 JSON 파일을 만듭니다. `schema_version`, `source.name`, `source.url`(HTTPS), `generated_at`, `indicators`가 필요합니다. 각 지표에는 고유한 `id`, `type`(`domain` 또는 `ip`), `value`, `description`, 시간대가 포함된 `valid_from`과 `valid_until`을 입력합니다. 최대 25 MiB / 100,000개까지 허용하며 형식이 잘못되면 분석을 중단합니다. 출처는 파일 작성자가 제공하므로 신뢰성을 별도로 확인해야 합니다.

### STIX·TAXII 입력

`import-stix`는 STIX 2.1 bundle에서 도메인·IPv4·IPv6의 정확한 일치, 단순 `OR`와 `IN`을 기존 피드로 변환합니다. 복합 패턴은 이 과정에서 분리하지 않고 건너뜁니다. `OR`·`IN` 지표의 각 대안에는 원본 ID와 대안 번호를 부여합니다. 폐기된 지표는 가져오지 않으며, 동일 ID의 여러 버전은 오류로 처리합니다. 공유 제한 표시가 있는 지표는 전체 가져오기를 중단합니다. 유효 종료일이 없으면 시작일로부터 30일을 PathLens의 임시 기준으로 적용하고 설명에 표시합니다.

```bash
pathlens import-stix examples/sample-stix.json --output /tmp/pathlens-stix-demo.json \
  --source-name 'Synthetic example' --source-url https://example.com/stix
```

명시적으로 접근 허가된 TAXII 2.1 collection의 `/objects/` HTTPS 주소도 입력할 수 있습니다. 인증 없음, HTTP Basic과 Bearer 방식을 지원합니다. 인증 정보는 명령행 인자가 아니라 실행 중 입력받으며 피드 파일에 기록하지 않습니다. 입력한 서버로 인증 정보가 전송되므로 주소와 권한을 먼저 확인하세요. URL에 인증 정보·쿼리 문자열을 넣을 수 없으며 리디렉션은 따라가지 않습니다. `next` 토큰 방식 페이지 이동을 지원하고, 페이지가 불완전하거나 제한을 넘으면 가져오기를 중단합니다. 임시 로컬 TLS 서버의 Basic 인증은 테스트하지만, 실제 외부 인증 서버와의 실연은 아직 검증하지 않았습니다.

```bash
pathlens import-taxii --url https://YOUR-AUTHORIZED-SERVER/api/collections/ID/objects/ \
  --source-name 'Authorized collection' --output /tmp/pathlens-taxii.json
```

Basic 또는 Bearer 인증이 필요한 경우 `--auth-method basic` 또는 `--auth-method bearer`를 추가하세요. 비밀번호와 토큰은 보이지 않게 입력받습니다. 인증 정보와 제한된 피드는 공개 저장소에 올리지 마세요.

`check-taxii`는 collection에 한 페이지를 요청하고 접근 여부만 표시합니다. 원본 객체는 저장하거나 출력하지 않습니다. HTTP 401과 403 등은 오류 코드로 구분합니다. 서버가 요청의 `limit`을 무시할 수도 있으므로 응답 크기 제한도 적용합니다. 접속 성공은 서버가 인증을 실제로 요구했는지까지 증명하지 않습니다.

```bash
pathlens check-taxii --url https://YOUR-AUTHORIZED-SERVER/api/collections/ID/objects/ \
  --auth-method basic
```

공개 TAXII 2.1 피드인 [dPhish](https://dphish.com/feeds/)에서 인증 없이 한 페이지를 읽는 연결을 확인했습니다. Basic·Bearer는 로컬 TLS 테스트에서 검증했지만, **실제 외부 인증 서버에 대한 검증은 아직 하지 못했습니다**.

### 복합 STIX 패턴 평가 (실험 기능)

`evaluate-stix`는 원본 indicator bundle과 관측 데이터를 별도로 받아 패턴을 평가합니다. `AND`, `MATCHES`, `START/STOP`, `WITHIN`, `FOLLOWEDBY`, `REPEATS`를 포함한 예제를 테스트했습니다. `import-stix`로 만든 피드가 아니라 **변환 전의 indicator bundle**을 사용합니다.

```bash
python -m pip install -e '.[stix]'
pathlens evaluate-stix examples/stix-pattern-indicators.json examples/stix-observations.json
pathlens evaluate-stix examples/stix-pattern-indicators.json examples/sample.json --snapshot
```

같은 평가를 `scan`에 선택적으로 포함하려면 아래처럼 `--stix-bundle`을 지정합니다. 결과는 `report.json`의 `stix_correlation`과 `report.md`의 별도 섹션에 들어가며 각 일치에 DNS 근거가 표시됩니다. MCP의 `analyze_snapshot`과 `scan_domain`에도 `stix_bundle` JSON 객체를 전달할 수 있습니다. 결과는 개별 자산의 침해로 자동 귀속하지 않으며 기존 우선순위를 변경하지 않습니다.

```bash
pathlens scan example.com --snapshot examples/sample.json \
  --stix-bundle examples/stix-snapshot-indicators.json --output pathlens-output/stix-example
```

허가된 TAXII collection의 원본 패턴을 보존하려면 `import-taxii`에 `--raw-stix`를 추가합니다. 공유 제한 표시가 있는 객체는 저장을 거부하고, 파일은 로컬에서 소유자만 읽고 쓸 수 있게 생성합니다. 원본은 기존 `--threat-feed` 형식이 아니며, 제공자의 이용·보관 조건을 직접 확인해야 합니다. 원본이 20개 지표를 넘으면 `evaluate-stix`에서 `--indicator-id`를 반복해 평가할 ID를 최대 20개까지 선택합니다. 데이터를 임의로 잘라내지 않습니다.

관측 입력은 도메인·IPv4·IPv6 값과 각각의 정확한 관측 시각만 지원합니다. `--snapshot`은 PathLens 스냅샷의 범위 내 DNS 응답을 관측 자료로 변환하며, 결과의 `snapshot_dns_record_indexes`는 원본 `dns_records`의 0부터 시작하는 위치입니다. `scan`에서는 분석 대상 자산에 속하는 범위 내 DNS 응답만 사용합니다. 분석 가능한 DNS 응답은 최대 25개이며 제한을 넘으면 오류를 반환하고 임의로 잘라내지 않습니다. DNS 응답에 함께 나온 값은 한 관측으로 취급합니다. 다른 관측 간 `AND`가 일치해도 두 대상이 서로 연결됐거나 악성이라는 뜻은 아닙니다. 인증서와 범위 밖 DNS 레코드는 이 변환에서 제외합니다.

패턴 및 관측 수를 제한하고 별도 프로세스에서 평가하며 CPU·시간과 메모리 사용을 제한하거나 감시합니다. macOS의 메모리 감시는 최선의 보호이며 격리된 보안 샌드박스가 아닙니다. 지원하지 않는 속성, 시간 초과, 근거 부족, 처리 오류는 `indeterminate`로 표시합니다. `not_matched`는 **제공된 관측 데이터에서 일치하지 않았다**는 의미이지 안전하다는 뜻이 아닙니다. 참조 매처의 `WITHIN` 경계 문제를 피하기 위해 경계가 모호한 결과는 검토 필요로 표시합니다. OASIS 매처 자체가 프로토타입이므로 모든 STIX 패턴의 정확성이나 전체 STIX 유효성 검증을 보장하지 않습니다. Linux·macOS에서만 실험적으로 사용하고, 실제 운영 판단에는 별도 검증이 필요합니다. 공유 제한 표시가 있는 입력은 평가를 거부합니다.

### 피드의 주기적 갱신

다음 명령은 실행 중인 **포그라운드 프로세스**에서만 Feodo 피드를 갱신합니다. 지정한 폴더가 미리 있어야 하며 각 결과는 새 파일로 저장됩니다. 종료하려면 Ctrl+C를 누르세요. 기본 간격은 1시간이며 최소 5분입니다.

```bash
pathlens watch-feodo --directory /tmp --interval 3600
```

macOS에서는 `make-launch-agent`가 백그라운드 주기 갱신용 설정 파일을 생성할 수 있습니다. 파일 생성만 하며, 사용자의 시스템에 등록하거나 실행하지 않습니다. Python 경로는 PathLens가 설치된 환경의 절대 경로여야 합니다. 파일을 생성하기 전 경로를 본인의 환경에 맞게 바꾸세요.

```bash
pathlens make-launch-agent --python /absolute/path/to/venv/bin/python \
  --directory /absolute/path/to/feed-directory --interval 3600 \
  --output /absolute/path/to/org.pathlens.feodo-refresh.plist
```

생성한 설정을 macOS에 등록하는 것은 별도의 사용자 작업입니다. 다음 명령의 파일 경로를 생성한 plist의 실제 절대 경로로 바꾼 뒤에만 실행하세요. 등록하면 Feodo에 주기적으로 접속하고 지정한 폴더에 새 스냅샷이 쌓입니다. 중지해도 기존 파일은 삭제하지 않습니다.

```bash
launchctl bootstrap "gui/$(id -u)" /absolute/path/to/org.pathlens.feodo-refresh.plist
launchctl print "gui/$(id -u)/org.pathlens.feodo-refresh"
launchctl bootout "gui/$(id -u)/org.pathlens.feodo-refresh"
```

다시 로그인한 뒤에도 사용하려면 macOS의 사용자 LaunchAgents 경로와 소유권·권한 요구사항을 별도로 확인해야 합니다. 절전 중 놓친 실행은 건너뛰어질 수 있습니다. 개발 환경에서 임시 등록 후 즉시 1회 실행해 스냅샷 생성을 확인하고 등록을 해제했습니다. 장시간 반복 실행이나 재로그인 후 동작은 확인하지 않았습니다.

### CVE와 CISA KEV 연결

사용자가 자산과 CVE 사이의 단서를 입력하고 CISA KEV 목록을 별도로 제공하면, 정확한 CVE 번호를 대조합니다. AWS 서비스 이름이나 IP만으로 CVE를 추측하지 않습니다. 입력한 자산·CVE 연결과 입력한 KEV 파일의 진위는 별도로 확인해야 하며, KEV에 있다는 사실은 해당 자산이 취약하거나 침해됐다는 뜻이 아닙니다.

```bash
pathlens update-kev --output /tmp/pathlens-kev.json
pathlens scan example.com --snapshot examples/sample.json \
  --cve-observations examples/cve-observations.json \
  --kev-catalog examples/kev-sample.json --output pathlens-output/cve-example
```

위 예제의 CVE와 KEV 항목은 모두 가짜입니다. 실제 사용 시에는 `--kev-catalog`에 CISA에서 받은 파일과 허가된 자산에 대한 근거를 사용하세요. 두 파일은 함께 제공해야 합니다.

`examples/product-observations.json`처럼 자산의 제품명에 대한 단서를 제공하면, CISA KEV에서 **벤더명과 제품명이 정확히 일치하는 CVE 후보**를 자동으로 연결할 수 있습니다. `--fetch-kev`를 지정하면 분석 시 CISA의 공개 목록을 직접 가져오며 대상 도메인은 CISA에 전송하지 않습니다. 제품의 배포 여부와 버전·취약 여부는 확인하지 않으므로 결과는 후보일 뿐입니다. 카탈로그의 제품명과 정확히 다르면 일치하지 않을 수 있습니다.

```bash
pathlens scan example.com --snapshot examples/sample.json \
  --product-observations examples/product-observations.json \
  --kev-catalog examples/kev-sample.json --output pathlens-output/product-example
```

실제 목록 사용 시 `--kev-catalog` 대신 `--fetch-kev`를 지정할 수 있습니다. 두 옵션을 동시에 사용할 수 없습니다.

### OSV 패키지 버전별 권고 조회

`examples/osv-observations.json`처럼 사용자가 제공한 패키지명·생태계·버전으로 OSV의 버전별 조회 결과를 연결할 수 있습니다. 현재 PyPI와 npm만 지원하며, 조회할 때 **패키지명·버전·생태계가 OSV로 전송**됩니다. 자산 도메인과 근거 URL은 전송하지 않습니다. 목록에 민감한 내부 패키지명이 포함되어 있다면 외부 조회를 하지 마세요.

```bash
pathlens scan example.com --snapshot examples/sample.json \
  --osv-observations examples/osv-observations.json \
  --osv-results examples/osv-sample.json --output pathlens-output/osv-example
```

위 예제의 패키지와 권고는 가짜이며 네트워크를 사용하지 않습니다. 실제 조회는 `--osv-results` 대신 `--fetch-osv`를 명시해야 합니다. OSV는 버전을 유사하게 매칭할 수 있고, PathLens는 실제 패키지 배포·버전·악용 가능성을 확인하지 않습니다. 빈 결과도 안전을 보장하지 않습니다. 입력 파일로 제공된 결과는 출처가 검증되지 않은 사용자 제공 데이터로 표시합니다. 조회가 실패하거나 페이지가 누락되면 분석을 중단합니다.

### 유출 주장 입력

`examples/exposure-observations.json`처럼 사용자가 적법하게 확보한 **주장의 최소 메타데이터**만 입력할 수 있습니다. 도메인, 분류, 출처, 시각만 받으며 비밀번호·토큰·이메일·유출 원문 필드는 허용하지 않습니다. 출처 이름이나 URL에도 민감정보를 넣지 마세요. PathLens는 다크웹에 접속하거나 내용을 검증하지 않으며, 결과는 사용자 제공의 미검증 주장입니다.

```bash
pathlens scan example.com --snapshot examples/sample.json \
  --exposure-observations examples/exposure-observations.json \
  --output pathlens-output/exposure-example
```

현재 자동 다크웹 수집, 모든 STIX 패턴, 자산 소유권·실제 취약점·침해 확인은 지원하지 않습니다. 각 입력에 대한 제공처의 권한과 이용 조건을 사용자가 확인해야 합니다.

보고서 JSON에 `threat_feed`, `stix_correlation`, 자산별 `threat_context`, `indicator_matches`가 포함됩니다. 기존 결과를 사용하는 연동 코드에서는 이 필드를 허용해야 합니다. 생성하는 보고서와 관측 파일은 소유자만 읽고 쓸 수 있는 권한으로 만듭니다.

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
- [AWS Elastic Beanstalk domain names](https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/customdomains.html)
- [Feodo Tracker blocklists](https://feodotracker.abuse.ch/blocklist/)
- [OASIS TAXII 2.1](https://docs.oasis-open.org/cti/taxii/v2.1/os/taxii-v2.1-os.html)
- [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [OSV version query API](https://google.github.io/osv.dev/post-v1-query/)
- [MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk)

## 라이선스

MIT. 자세한 내용은 [LICENSE](LICENSE)를 확인하세요.

