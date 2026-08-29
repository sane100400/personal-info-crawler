# 개인정보 불법유통 게시물 크롤러

공개 웹에서 개인정보 불법유통 **후보 페이지**를 수집하고, 개인정보를 즉시 마스킹해 연구용 데이터와 탐지내역 Excel 양식으로 정리하는 크롤러입니다.

이 저장소는 KISA의 공식 연구·위탁과제·공식 탐지 도구가 아닙니다. 자동 수집 결과는 정탐 판정이 아니며 제출 전 반드시 사람이 검토해야 합니다.

## 핵심 기능

- 비공개 YAML 검색어 또는 비공개 URL 시드에서 후보 생성
- 네이버 통합·블로그·카페·지식인·뉴스와 Bing/DuckDuckGo/Google 공개 검색 결과 어댑터
- HTTP(S)·공개 IP만 허용하는 DNS/리다이렉트 검증
- robots 정책, 도메인별 요청 간격, 응답 크기·MIME 제한
- 제목·본문 추출 및 전화번호·이메일·주민번호 등 즉시 마스킹
- 팀 공유용 `data.csv`에 메신저 ID와 원문 URL 보존
- Trafilatura·`main/article`·가시 본문 순의 다단계 추출과 본문 길이·언어 품질 검사
- 원 URL과 최종 URL을 HMAC-SHA256으로 가명화
- SimHash 기반 유사문서 지문과 연락처 HMAC 기반 캠페인 식별자 생성
- 연구계획의 23필드 CSV 및 `(양식) 탐지내역.xlsx` 기반 제출 파일 생성
- 중단 후 재개, 25건 단위 체크포인트, 성공·실패 로그와 실행 요약
- 성공한 공개 페이지의 게시물형 내부 링크 확장, 후보 풀·도메인당 상한
- 네이버 블로그 프레임 페이지의 공개 모바일 본문 대체 추출

## 안전 경계

이 크롤러는 다음 기능을 제공하지 않습니다.

- 로그인 또는 인증 세션 사용
- CAPTCHA 자동 해결, 접근통제 우회, 프록시/IP 회전, 스텔스 기능
- 판매자 연락, 구매·문의, 거래 시도
- 첨부파일·이미지·유출 DB·샘플 파일 다운로드
- 외부 LLM API로 원문 전송

검색엔진이 차단 화면을 반환하면 우회하지 않고 다른 공개 어댑터로 전환합니다. 대상 페이지가 명시적으로 robots 수집을 금지하면 제외합니다.

## 처리 흐름

```text
비공개 검색어/시드
  → 검색 결과 URL 후보
  → URL·DNS·robots·rate limit 검증
  → HTML 1MB 이내 수집
  → 본문 추출
  → 개인정보 마스킹·URL HMAC
  → 중복/캠페인 지문
  ├─ 연구용 23필드 CSV
  └─ 제한 폴더의 탐지내역 Excel(원 URL 포함)
```

검색결과 페이지 자체는 표본으로 저장하지 않고 최종 도착 페이지의 콘텐츠만 처리합니다.

## 설치

Python 3.11 이상과 Chrome/Chromium이 필요합니다. 브라우저 검색은 로컬 CDP 세션을 사용하므로 `agbrowse`도 설치되어 있어야 합니다.

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -e .
```

## 비공개 입력 준비

운영 검색어는 논문·공개 저장소·Discord에 게시하지 않습니다.

```bash
cp config/queries.example.yaml config/queries.local.yaml
```

`config/queries.local.yaml` 형식:

```yaml
groups:
  - name: internal_group_name
    detection_type: 개인정보DB  # 개인정보DB/여권 및 통장/포털ID/해킹대행/기타
    queries:
      - "연구책임자가 승인한 비공개 검색어"
```

이미 확보한 공개 URL이 있다면 `config/seeds.example.csv`와 같은 CSV를 `config/seeds.local.csv`로 만들어 사용할 수 있습니다. 필수 열은 `url`, 선택 열은 `detection_type`, `query_group`입니다. 줄마다 URL 하나를 적은 텍스트 파일과 크롤러가 비공개 폴더에 저장한 JSONL 후보 큐도 지원합니다.

## 실행

검색어 기반 수집:

```bash
agbrowse start --headless
personal-info-crawl \
  --queries config/queries.local.yaml \
  --registrant "등록자 이름" \
  --target 200
```

URL 시드 기반 수집:

```bash
personal-info-crawl \
  --seed-file config/seeds.local.csv \
  --registrant "등록자 이름" \
  --target 200
```

AI 판정 없이 한글 본문 후보 2,000건을 수집하는 예:

```bash
personal-info-crawl \
  --queries config/queries.local.yaml \
  --target 2000 \
  --skip-detection-workbook \
  --query-variants 1 \
  --relevance-gate review \
  --search-pages 3 \
  --follow-links-per-page 10 \
  --candidate-pool-limit 8000 \
  --max-candidates-per-domain 200 \
  --min-text-chars 80 \
  --min-korean-chars 10 \
  --checkpoint-every 25 \
  --out output/crawl_2000_ko
```

중단된 작업 재개:

```bash
personal-info-crawl \
  --queries config/queries.local.yaml \
  --registrant "등록자 이름" \
  --target 200 \
  --resume
```

Google HTML 검색이 CAPTCHA를 반환하는 환경에서는 이를 우회하지 않습니다.
기존 Custom Search JSON API 고객은 API 키와 검색엔진 ID를 환경변수에 넣어
공식 JSON API를 우선 사용할 수 있습니다. 이 API는 2026년 현재 신규 고객에게
제공되지 않으며 기존 고객도 2027년 1월 1일까지 대체 수단으로 이전해야 합니다.
API 호출량과 과금 정책은 실행 전에 Google Cloud 설정에서 확인해야 합니다.
정책 기준은 [Google 공식 안내](https://developers.google.com/custom-search/v1/overview)를
따릅니다.

```bash
export GOOGLE_CSE_API_KEY="발급받은 API 키"
export GOOGLE_CSE_ID="Programmable Search Engine ID"
personal-info-crawl \
  --queries config/queries.local.yaml \
  --target 500 \
  --skip-detection-workbook \
  --search-provider google_api \
  --search-provider bing \
  --relevance-gate review \
  --keyword-expansion-rounds 2 \
  --keyword-expansion-per-round 20 \
  --keyword-expansion-min-domains 2 \
  --min-type-share 0.05 \
  --out output/crawl_google_review
```

기존 API 이용 권한이 없다면 `google_api` 옵션을 사용할 수 없습니다. 이 경우
사람이 Google에서 확인해 내부 파일로 전달한 공개 결과 URL을 `--seed-file`로
수집하거나, 팀 승인을 받아 별도 검색 API를 정한 뒤 어댑터를 추가해야 합니다.

운영 검색어는 완성된 문장이나 따옴표 구문 검색보다 `대상어 + 거래·연락 신호`로
이루어진 짧은 단어 조합을 사용합니다. 예를 들어 대상어 한 개와 보조어 한두 개를
조합하고 `--strict-search`는 사용하지 않습니다. 검색 단계에서는 표현 변형을 넓게
발견하고, `--relevance-gate review` 또는 `strict`가 목적지 본문에 나타난 대상·직접
거래 의사·구체적 연락수단을 확인합니다.

키워드 확장은 정탐 신호가 강한 검색 요약에서 `디비/DB/아이디/계정` 계열
대상어와 `텔그/텔레그램/판매/거래` 계열 보조어가 가까이 나타난 짧은 조합만 다음
라운드 검색어로 추가합니다. 원본 YAML은 수정하지 않으며, 채택된 조합과 문서·
도메인 빈도는 `output/.private/keyword_expansions.csv`에 기록합니다.

주요 옵션:

| 옵션 | 기본값 | 설명 |
|---|---:|---|
| `--target` | 200 | 최종 성공 표본 수 |
| `--search-pages` | 2 | 검색어별 검색결과 페이지 수 |
| `--search-provider` | 전체 | 검색 공급자 선택(`naver`, `daum`, `daum_blog`, `bing` 등), 반복 지정 가능 |
| `--google-api-key-env` | `GOOGLE_CSE_API_KEY` | Google 검색 API 키를 읽을 환경변수 이름 |
| `--google-cse-id-env` | `GOOGLE_CSE_ID` | Google Programmable Search Engine ID 환경변수 이름 |
| `--provider-stale-pages` | 12 | 새 후보가 연속으로 나오지 않을 때 다음 검색 공급자로 전환할 기준 |
| `--search-delay` | 3초 | 검색 요청 사이의 대기 시간 |
| `--domain-delay` | 2초 | 동일 호스트 요청 사이의 최소 간격 |
| `--query-variants` | 1 | 검색어별 자동 변형 개수 |
| `--strict-search` | 비활성 | 따옴표 구문 일치 검색과 일반 문서 제외 검색어 적용(정밀도 비교 실험용) |
| `--relevance-gate` | `off` | 목적지 본문 선별: `off`, `labeling`, `review`, `intent`, `strict` |
| `--discovery-relevance-gate` | 본문 필터와 같음 | 검색 결과 요약에 적용할 1차 선별 수준 |
| `--seed-file` | 없음 | URL 시드 파일. 서로 다른 출처 묶음을 합칠 때 반복 지정 가능 |
| `--seed-offset` | `0` | 앞선 파일럿에서 확인한 시드 후보 수를 건너뛰어 새 구간을 검증 |
| `--exclude-csv` | 없음 | 이전 표본의 URL·문서 지문을 제외하며 여러 번 지정 가능 |
| `--keyword-expansion-rounds` | 0 | 고관련 검색 요약으로 반복 검색할 키워드 확장 횟수 |
| `--keyword-expansion-per-round` | 20 | 확장 라운드마다 추가할 최대 검색어 수 |
| `--keyword-expansion-min-domains` | 2 | 확장어 채택에 필요한 서로 다른 출처 도메인 수 |
| `--min-text-chars` | 80 | 성공 건으로 인정할 최소 추출 본문 길이 |
| `--min-korean-chars` | 0 | 제목·본문에 필요한 최소 한글 음절 수 |
| `--follow-links-per-page` | 0 | 본문 성공 페이지에서 추가할 게시물형 내부 링크 수 |
| `--candidate-pool-limit` | 목표×4 | 내부 링크를 포함한 최대 후보 수 |
| `--max-candidates-per-domain` | 100 | 검색 발견·내부 링크 확장을 합친 도메인당 후보 상한 |
| `--max-candidates-per-source-unit` | 10 | 같은 SNS 계정·채널 또는 게시판에서 확인할 후보 상한 |
| `--max-records-per-domain` | 0 | 최종 표본의 도메인별 절대 상한. 0이면 절대 상한 없음 |
| `--max-domain-share` | 0 | 최종 표본의 단일 도메인 비율 상한. SNS 계정 다양성을 위해 기본 비활성 |
| `--max-records-per-source-unit` | 1 | 같은 SNS 계정·채널 또는 게시판에서 남길 대표 게시물 수 |
| `--min-domains` | 0 | 완료 판정에 필요한 최소 도메인 수. 필요할 때 별도 지정 |
| `--min-type-share` | 0.05 | DB·계정/인증·통장/계좌·신분증/여권 유형별 최소 비율 |
| `--max-records-per-campaign` | 1 | 동일 연락처 캠페인에서 보존할 최대 대표 게시물 수 |
| `--refresh-discovery` | 비활성 | 재개할 때 저장된 후보 큐 대신 검색을 다시 실행해 새 URL을 추가 |
| `--expand-existing-links` | 비활성 | 기존 성공 페이지는 중복 저장하지 않고 관련 내부 글 발견에만 사용 |
| `--checkpoint-every` | 25 | CSV·로그·후보 큐를 저장할 실제 수집 시도 횟수 간격 |
| `--skip-detection-workbook` | 비활성 | 원 URL Excel 없이 마스킹 CSV만 생성 |
| `--cdp` | `127.0.0.1:9222` | 격리 Chrome CDP 주소 |
| `--template` | `(양식) 탐지내역.xlsx` | 제출 양식 원본 |
| `--out` | `output` | 결과 디렉터리 |

## 결과 파일

| 파일 | 내용 | 공개 가능 여부 |
|---|---|---|
| `output/candidates_masked.csv` | 마스킹된 연구용 데이터 | 검토 후 제한 공유 |
| `output/collection_log.csv` | 시각을 포함한 성공·실패·제외 사유, URL HMAC | 내부 공유 |
| `output/extraction_failures.csv` | 본문 추출 실패·부분 실패 사유 | 내부 공유 |
| `output/collection_summary.json` | 수집량과 안전 경계 요약 | 내부 공유 |
| `output/masking_validation_report.json` | 잔존 이메일·전화번호·주민번호·URL 검사 | 내부 공유 |
| `output/data_manifest.json` | 설정·코드 버전과 파일별 SHA-256 | 내부 공유 |
| `output/restricted/탐지내역_자동수집.xlsx` | 원 URL이 포함된 제출 양식 | 외부 공개 금지 |
| `output/label.xlsx` | 원문 링크와 정오탐·메모 칸이 있는 라벨링 파일 | 연구팀 공유 |
| `output/data.csv` | 원문 URL·메신저 ID를 보존한 6열 검토용 데이터 | 연구팀 공유 |
| `output/.private/url_hmac_key` | URL HMAC 비밀키 | 절대 공유 금지 |
| `output/.private/keyword_expansions.csv` | 자동 확장 검색어와 근거 빈도 | 외부 공개 금지 |

`output/`과 로컬 검색어·시드 파일은 `.gitignore`에 포함됩니다. `data.csv`와 `label.xlsx`는 팀원이 읽을 수 있도록 권한 644로 생성됩니다. 제출용 Excel과 `.private`의 HMAC 키·수집 상태 파일은 계속 권한 600으로 제한합니다.

여러 정밀 수집 결과에서 라벨링 파일럿을 구성할 때는 우선순위가 높은 결과를
`--source` 순서대로 지정합니다. 부족한 수량만 `--fallback-source`에서 채웁니다.

```bash
python3 -m collector.build_labeling_pilot \
  --source output/precision_run_1 \
  --source output/precision_run_2 \
  --fallback-source output/review_run \
  --target 35 \
  --intent-priority \
  --max-per-domain 20 \
  --out output/handoff_35
```

`--intent-priority`는 개인정보 거래 대상과 직접적인 판매·매입·제작 의사가
확인된 후보를 연락수단 유무와 관계없이 먼저 배치합니다. 실제 개인정보가
본문에 포함되어 있는지는 정탐 조건으로 사용하지 않습니다. 남은 수량은 경계
사례와 명시적 오탐 후보를 제외 사유별로 번갈아 채웁니다. 연락수단까지 확인된
후보만 우선하려면 대신 `--strict-priority`를 사용합니다.
`--max-per-domain`은 한 도메인이 라벨링 묶음을 과도하게 차지하지 않도록
제한합니다. 이 우선순위는 자동 정답이 아니며 모든 최종 라벨은 계속
`uncertain`으로 생성됩니다.

인계 폴더에는 라벨을 비운 `label_A.csv`와 `label_B.csv`, `guide.md`,
`masking.json`, `manifest.json`이 생성됩니다. 원 URL 대응표는
`.private/urls.csv`에 기록됩니다. 원문 확인이 필요한 내부 라벨러용 파일은
`links/label.xlsx`이며, 원문 링크와 `정탐·오탐·보류` 드롭다운 및 메모 칸을
포함합니다. 독립 이중 라벨링이 필요할 때는 `links/label_A.csv`와
`links/label_B.csv`를 사용합니다. 링크 포함 파일은 모두 권한 600으로 제한하며
외부 공유본과 분리합니다.

## 데이터 필드

연구용 CSV는 다음 필드를 사용합니다.

```text
sample_id, collected_at, source_type, registrable_domain,
source_unit_kind, source_unit_hmac,
url_hmac, http_status, final_url_hmac, page_type, live_status,
extraction_status,
masked_title, masked_text, language_mix, obfuscation_type,
intent_label, target_label, contact_label, final_label,
evidence_spans, annotator_1, annotator_2, adjudicated_label,
near_duplicate_cluster, near_duplicate_fingerprint, campaign_group
```

수집 단계에서는 요소별 라벨을 비워두고 `final_label=uncertain`으로 저장합니다. 라벨링 담당자가 원 페이지 여부, 거래 의사·대상·연락수단을 독립적으로 판정해야 합니다.
`near_duplicate_cluster`는 기존 소비자 호환용 별칭이며 실제 값은
`near_duplicate_fingerprint`와 같은 SimHash 지문입니다. 지문이 완전히 같은 본문은
수집 단계에서 제외하고, 비슷하지만 지문이 다른 문서의 중복 군집은 후처리에서 구성합니다.
`--discovery-relevance-gate`는 검색 요약에 적용하는 예비 필터이고,
`--relevance-gate`는 목적지 본문에 적용합니다. 검색 요약이 짧을 때는 전자를
`review`, 후자를 `intent`로 두어 후보를 놓치지 않으면서 본문 오탐을 줄입니다.
`review`는 개인정보 대상과 거래·연락 신호 중 하나가 같은 문맥에 있으면 남기고,
`intent`는 연락수단과 관계없이 직접 거래 의사를 요구하며, `strict`는 구체적인
연락수단까지 요구합니다.
`off`는 주제 관련성만 선별하지 않으며 검색결과·검색어 반영 페이지 같은
구조적 비본문 페이지는 모든 모드에서 제외합니다.

`intent`와 `strict`에서는 기사·재게시 기사, 거래 위험 안내문, 정상 신분증
상품·촬영 소품, 게임 계정, 상품권 거래, 텔레그램 빈 셸, 게시판 목록,
다품목 키워드 도배와 서비스 문구에 계정 키워드를 삽입한 SEO 스팸을 먼저
제외합니다. 목록 페이지는 표본에 저장하지 않지만, 같은 사이트의 개별 거래글을
찾기 위한 링크 탐색에는 사용할 수 있습니다.

짧은 단어 조합으로 재현율을 먼저 확보한 뒤 정밀도를 높이려면 같은 URL을 다시
검색하지 않고 검토 실행의 비공개 후보 큐를 엄격 실행의 시드로 사용합니다.

```bash
personal-info-crawl \
  --queries config/queries.local.yaml \
  --relevance-gate review \
  --target 60 \
  --out output/review_run

personal-info-crawl \
  --seed-file output/review_run/.private/candidate_queue.jsonl \
  --relevance-gate strict \
  --target 60 \
  --out output/strict_run
```

두 번째 실행은 검색요약 근거가 있는 후보에 엄격 게이트를 먼저 적용해 목적지
요청 수를 줄입니다. 사람이 직접 넣은 URL 시드는 검색요약이 없으므로 제외하지
않고 본문을 확인합니다.

## 테스트

```bash
python3 -m unittest discover -s tests -v
python3 -m compileall -q collector tests
```

실제 검색·수집 검증은 공개 페이지 1건으로 수행하고, 생성된 파일에 원 개인정보가 남지 않았는지 별도로 확인해야 합니다.

## 알려진 한계

- 이미지·영상에만 존재하는 정보는 추출하지 않습니다.
- JavaScript 렌더링이 필수인 본문은 1차 버전에서 실패로 기록될 수 있습니다.
- 자동 `탐지유형`은 검색 그룹의 설정값을 우선하므로 최종 제출 전에 검토가 필요합니다.
- SimHash 값은 유사문서 지문이며, 실제 클러스터는 후처리에서 Hamming distance를 기준으로 구성해야 합니다.
- 공개 웹 자료라도 개인정보 보호 의무가 사라지지 않으므로 기관 연구윤리·IRB 담당 부서의 검토를 권장합니다.
