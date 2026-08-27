# 공개 웹 후보 수집기

공개 웹 후보를 수집해 `(양식) 탐지내역.xlsx`의 6개 열(번호·탐지일·탐지 URL·탐지유형·등록자·비고)에 맞춰 정리하는 크롤러입니다. 연구용 내부 데이터는 연구계획서와 모델링팀 인계 기준에 맞춰 별도 저장합니다.

## 안전 경계

- 로그인, 캡차 해결, 접근통제 우회, IP 회전 기능이 없습니다.
- 검색엔진이 차단 화면을 반환하면 이를 우회하지 않고 다음 공개 검색 어댑터로 전환합니다.
- 검색결과 페이지는 URL 발견에만 사용하며 데이터 표본으로 저장하지 않습니다.
- robots 정책이 명시적으로 금지한 페이지는 수집하지 않습니다.
- HTML 본문만 최대 1MB까지 읽고 첨부파일·이미지·유출 샘플은 내려받지 않습니다.
- 원 URL은 제출 양식에 필요하므로 권한이 제한된 Excel 파일에만 기록합니다. 연구용 CSV와 로그에는 HMAC-SHA256 식별자만 남깁니다.
- 연락처·이메일·메신저 ID·계정명·주민번호·계좌번호 등은 수집 즉시 placeholder로 바꿉니다.
- 외부 LLM API에는 아무 데이터도 전송하지 않습니다.

## 실행

전체 설치·설정·데이터 필드 설명은 저장소 루트의 `README.md`를 참고하세요. 먼저 격리된 headless Chrome을 시작합니다.

```bash
python3 -m pip install -r requirements.txt
agbrowse start --headless
python3 collector/collect_candidates.py \
  --queries config/queries.local.yaml \
  --target 200 \
  --registrant "홍길동"
```

AI 판정 없이 한글 본문 후보를 대량 수집할 때는 `--skip-detection-workbook`,
`--min-text-chars`, `--min-korean-chars`, `--follow-links-per-page`를 함께 사용합니다.
게시물형 내부 링크만 추가하며, `--candidate-pool-limit`과
`--max-candidates-per-domain`으로 확장 범위를 제한합니다.
일반 문서 혼입을 줄이려면 `--strict-search --relevance-gate review`를
사용합니다. 이 게이트는 개인정보 대상과 거래·연락 표현의 근접 여부만
확인하며 AI 판정이나 최종 라벨을 대신하지 않습니다. 본문을 보존하기 전
동일한 SimHash 지문이 이미 있으면 중복 후보로 기록하고 표본에서는 제외합니다.

중간에 정상 종료되지 않았거나 수집 성공 건수가 부족하면 다음처럼 이어서 실행합니다.

```bash
python3 collector/collect_candidates.py \
  --queries config/queries.local.yaml \
  --target 200 \
  --registrant "홍길동" \
  --resume
```

네트워크를 사용하지 않는 기본 검증은 다음 명령으로 실행합니다.

```bash
python3 -m unittest discover -s tests -v
```

## 결과

- `output/candidates_masked.csv`: UTF-8 BOM CSV
- `output/restricted/탐지내역_자동수집.xlsx`: 원본 양식을 유지한 제출용 Excel(원 URL 포함, 권한 600)
- `output/collection_log.csv`: 성공·실패·robots 제외 내역(URL은 HMAC만 기록)
- `output/extraction_failures.csv`: 본문 추출 실패·부분 실패 사유
- `output/collection_summary.json`: 수집 요약과 안전 경계 확인
- `output/masking_validation_report.json`: 마스킹 잔존 패턴 검사 결과
- `output/data_manifest.json`: 코드·설정 버전과 파일별 SHA-256
- `output/.private/url_hmac_key`: URL HMAC 비밀키(권한 600, 외부 공유 금지)

양식의 탐지유형은 `개인정보DB`, `여권 및 통장`, `포털ID`, `해킹대행`, `기타` 중 하나로 1차 분류합니다. 이는 최종 정탐 판정이 아니므로 제출 전 사람이 URL과 유형을 검토해야 합니다. 연구용 라벨은 `final_label=uncertain`으로 두고 라벨링 담당자가 독립 판정합니다.
