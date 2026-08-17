# 개인정보 불법유통 게시물 크롤러

공개 웹에서 개인정보 불법유통 **후보 페이지**를 수집하고, 개인정보를 즉시 마스킹해 연구용 데이터와 탐지내역 Excel 양식으로 정리하는 크롤러입니다.

이 저장소는 KISA의 공식 연구·위탁과제·공식 탐지 도구가 아닙니다. 자동 수집 결과는 정탐 판정이 아니며 제출 전 반드시 사람이 검토해야 합니다.

## 핵심 기능

- 비공개 YAML 검색어 또는 비공개 URL 시드에서 후보 생성
- Bing/Google 공개 검색 결과 어댑터와 차단 화면 감지
- HTTP(S)·공개 IP만 허용하는 DNS/리다이렉트 검증
- robots 정책, 도메인별 요청 간격, 응답 크기·MIME 제한
- 제목·본문 추출 및 전화번호·이메일·메신저 ID·계정명 등 즉시 마스킹
- 원 URL과 최종 URL을 HMAC-SHA256으로 가명화
- SimHash 기반 유사문서 지문과 연락처 HMAC 기반 캠페인 식별자 생성
- 연구계획의 23필드 CSV 및 `(양식) 탐지내역.xlsx` 기반 제출 파일 생성
- 중단 후 재개, 10건 단위 체크포인트, 성공·실패 로그와 실행 요약

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

이미 확보한 공개 URL이 있다면 `config/seeds.example.csv`와 같은 CSV를 `config/seeds.local.csv`로 만들어 사용할 수 있습니다. 필수 열은 `url`, 선택 열은 `detection_type`, `query_group`입니다. 줄마다 URL 하나를 적은 텍스트 파일도 지원합니다.

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

중단된 작업 재개:

```bash
personal-info-crawl \
  --queries config/queries.local.yaml \
  --registrant "등록자 이름" \
  --target 200 \
  --resume
```

주요 옵션:

| 옵션 | 기본값 | 설명 |
|---|---:|---|
| `--target` | 200 | 최종 성공 표본 수 |
| `--search-pages` | 2 | 검색어별 검색결과 페이지 수 |
| `--search-delay` | 3초 | 검색 요청 사이의 대기 시간 |
| `--domain-delay` | 2초 | 동일 호스트 요청 사이의 최소 간격 |
| `--cdp` | `127.0.0.1:9222` | 격리 Chrome CDP 주소 |
| `--template` | `(양식) 탐지내역.xlsx` | 제출 양식 원본 |
| `--out` | `output` | 결과 디렉터리 |

## 결과 파일

| 파일 | 내용 | 공개 가능 여부 |
|---|---|---|
| `output/candidates_masked.csv` | 마스킹된 연구용 23필드 데이터 | 검토 후 제한 공유 |
| `output/collection_log.csv` | 성공·실패·제외 사유, URL HMAC | 내부 공유 |
| `output/collection_summary.json` | 수집량과 안전 경계 요약 | 내부 공유 |
| `output/restricted/탐지내역_자동수집.xlsx` | 원 URL이 포함된 제출 양식 | 외부 공개 금지 |
| `output/.private/url_hmac_key` | URL HMAC 비밀키 | 절대 공유 금지 |

`output/`과 로컬 검색어·시드 파일은 `.gitignore`에 포함됩니다. 제출용 Excel과 HMAC 키는 파일 권한 600, 상위 폴더 권한 700으로 생성됩니다.

## 데이터 필드

연구용 CSV는 다음 필드를 사용합니다.

```text
sample_id, collected_at, source_type, registrable_domain,
url_hmac, http_status, final_url_hmac, page_type, live_status,
masked_title, masked_text, language_mix, obfuscation_type,
intent_label, target_label, contact_label, final_label,
evidence_spans, annotator_1, annotator_2, adjudicated_label,
near_duplicate_cluster, campaign_group
```

수집 단계에서는 요소별 라벨을 비워두고 `final_label=uncertain`으로 저장합니다. 라벨링 담당자가 원 페이지 여부, 거래 의사·대상·연락수단을 독립적으로 판정해야 합니다.

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
