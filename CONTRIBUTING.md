# 고치는 방법

## 무엇을 어디서 고치나

| 고칠 내용 | 파일 | 주의 |
|---|---|---|
| 본문 문장·표·각주 | `source/guide/*.md` | 각주는 같은 파일 안에 정의한다(빌드가 점검). 근거 링크는 쓰지 않아도 빌드가 CWE·CERT·매뉴얼·SSDF·사례 파일 표기를 원문으로 바꾼다 |
| 환경별 지침(245건) | `source/data/env_{hw,os,tool,lang}.json` | ID(예: `MCU-03`)는 바꾸지 않는다. 지우는 대신 `"withdrawn": "사유"`를 단다 |
| 적용 조건·특성 | `source/data/guide_tags.json` | 조건식 문법: `특성 ∈ {값, …}`를 `∧`로 잇는다. 특성 목록(15개)을 늘리면 MINOR 판 이상 |
| 보안약점 점검 목록 44개 지침 | `source/data/common44.json` | 약점 이름은 행정안전부·KISA 가이드 항목명을 따른다 |
| 오픈소스 근거 | `source/data/evidence_*.json` | **원문을 태그로 고정한 URL**과 위치, 한글 주장을 넣는다. 원문 문장은 넣지 않는다. 확인하지 못한 근거는 `"verdict": "NEEDS_REVIEW"`로 두고 본문 사례로 쓰지 않는다 |
| 용어 | `source/data/glossary.json` | 표기 우선순위: 국립국어원 → TTA → 행정안전부·KISA → SPRi → 방위사업청 매뉴얼 → 현업 관용 |
| 근거 출처 목록 | `source/data/registry.json` | 새 표준·문서를 인용하면 키·제목·URL을 더한다 |
| 예시(나쁜 예·좋은 예) | `source/data/examples/cwe-<번호>.json` | 나쁜 예의 '공격'은 무해한 표식 출력(`echo INJECTED-RAN` 등), 문서용 예약 주소(`192.0.2.x`·`example.invalid`), 가짜 값만 쓴다. 셸코드·역방향 셸·실제 표적·실제 위치는 쓰지 않는다 |

## 근거 원칙

1. 사실 주장에는 근거 유형 [CWE]·[표준]·[사례]·[보완] 중 하나 이상을 붙인다.
2. 매뉴얼은 판과 위치를 적는다(예: 매뉴얼 제2024-6호 부록 7, 인쇄 7-10쪽).
3. 사례는 프로젝트·태그·`파일:행`과 확인일을 적는다. 브랜치(`main`) 주소는 쓰지 않는다.
4. 원문에 없는 수치를 계산해 넣으면 계산식을 각주로 남긴다.
5. 도구·표준·제품을 근거로 쓸 때는 판(버전)과 조회일을 함께 적는다(예: GCC 14.2.0 매뉴얼, 조회 2026. 10. 15.). 판이 바뀌면 사실이 달라질 수 있기 때문이다.

## 확인하고 올리기

```bash
python scripts/build.py          # 각주·링크 변환·생성
python -m mkdocs build --strict  # 깨진 링크가 있으면 실패
python scripts/site_build.py --offline  # (선택) 폐쇄망판(사이트·단일 문서) 빌드·점검·묶음
python scripts/check_links.py    # (선택) 외부 링크 접속 확인
```

끌어오기 요청(PR)을 열면 같은 점검이 자동으로 돈다.

**빌드 의존성.** CI는 해시를 고정한 `requirements-lock.txt`로만 설치한다(`pip install --require-hashes --no-deps`). `requirements.txt`의 판을 바꾸면 `python scripts/lock_requirements.py`로 잠금 파일을 다시 만들고, 고른 판에 알려진 취약점이 없는지(OSV)와 공개된 지 2주가 넘었는지 확인한다.

**반입한 자원.** 글꼴(IBM Plex, `source/assets/vendor/fonts/`)과 폐쇄망판 검색 셰임(`source/assets/vendor/iframe-worker-*.js`)은 저장소에 들어 있고, 빌드는 외부 서버에서 자원을 받지 않는다. 사이트의 `assets/vendor/`(와 혹시 생기는 `assets/external/`)는 `scripts/asset_hashes.json`의 해시와 같아야 한다(`check_assets.py`). 자원을 바꿀 때는 출처와 내용을 확인한 뒤에만 `python scripts/check_assets.py site --update`로 목록을 고친다.

## 판 번호 규칙 (SemVer)

| 올리는 자리 | 언제 | 예 |
|---|---|---|
| MAJOR (`2.0.0`) | 기준 문서가 바뀌어 지침 체계가 달라질 때(매뉴얼 새 판, CWE 큰 개정), 지침 ID 체계 변경 | 매뉴얼 제2026-x호 반영 |
| MINOR (`1.1.0`) | 지침·환경·특성 추가, 근거 대량 보강, 장·절 구조 변경 | Zephyr 환경 추가 |
| PATCH (`1.0.1`) | 오탈자, 문장 다듬기, 깨진 링크 교체, 근거 판정 정정 | 링크 갱신 |

발행 순서: `VERSION` 수정 → `mkdocs.yml`의 `extra.guide`(상태·기준일·기준 자료) 확인 → `CHANGELOG.md`와 독자용 `source/guide/changelog.md`에 항목 추가 → 커밋 → `git tag vX.Y.Z` → `git push origin vX.Y.Z`.

## 개정할 때 확인할 것

MINOR 이상 판을 낼 때는 다음을 다시 확인하고 결과를 `CHANGELOG.md`에 적는다.

1. **기준 문서의 판**: 「무기체계 소프트웨어 개발 및 관리 매뉴얼」 현행 판(지금은 제2024-6호), MITRE CWE 판(지금은 5.0), SSDF·행정안전부·KISA 가이드의 새 판이 나왔는지. 매뉴얼은 현행 판만 근거로 쓰고 이전 판은 연혁으로만 인용한다.
2. **인용한 도구·표준·제품의 판**: 지침 근거와 사례가 가리키는 판(컴파일러·정적 분석 도구·RTOS·SDK·MISRA·SEI CERT·오픈소스 태그 등)이 지원 종료되었거나 새 판에서 동작·옵션·기본값이 바뀌었는지. 바뀌었으면 근거를 새 판으로 다시 대조하고, 지침 문구나 환경 지침의 '제약과 대체'를 고친다. 지원 종료일이 지난 판(예: FreeRTOS 202406 LTS, 2026. 6. 30.)은 M-07 지침의 예시로 남기되 현행처럼 쓰지 않는다.
3. **링크 상태**: `python scripts/check_links.py`로 근거 링크를 확인하고 404·410은 태그 고정 주소나 보관본으로 바꾼다(매주 자동 점검 결과도 본다).
4. **수치 일치**: 원천 데이터가 바뀌었으면 `build.py`로 다시 생성해 본문·부록·도구·Excel이 같은 수치를 쓰는지 본다(8.7 예시 수치는 선택 도구로 다시 계산).

## 기여 조건

기여물은 이 저장소와 같은 [MIT 라이선스](LICENSE)로 제공한다. 기여자는 제출한 내용에 그 권리를 가지고 있음을 확인한다(소속 기관의 승인이 필요하면 받은 뒤 제출한다). 제3자 자료는 원문 문장 없이 공식 링크와 위치만 적고, 비공식 사본은 쓰지 않으며, 새 출처의 조건은 `NOTICE.md`에 적는다.
