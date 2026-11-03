# 내려받기

이 판(v{{VERSION}})과 같은 원천 데이터에서 만든 파일이다. 다음 판부터는 이전 판의 파일을 온라인판의 판 선택 메뉴에서 해당 판으로 이동해 내려받는다.

| 파일 | 내용 |
|---|---|
| [guide-data.xlsx](downloads/guide-data.xlsx) | 특성 목록, 환경 기본 특성, 기준선 활동 33개, 환경 지침 245건(적용 조건·근거 링크 포함), 오픈소스 근거(원문 링크·위치), 참조 프로젝트, 보안약점 점검 목록 44개, 보조 항목 4개, Microsoft .NET 보안 규칙 대응표(94개), Bandit 규칙 대응표(75개), 용어집, 근거 출처와 링크 확인 상태 |
| [cwe-phase-matrix.xlsx](downloads/cwe-phase-matrix.xlsx) | CWE 단계(스키마 열거값 17종)와 이 가이드 수명주기 5단계의 대응, 단계 집계(2.2 기준), 기준선 활동 33개, 보안약점 점검 목록 44개·언어 뷰 153개·보조 항목 4개의 단계별 지침, CWE 5.0 원문 완화책·탐지 방법·발생 단계와 한글 요지 |

**폐쇄망판.** 인터넷이 없는 환경에서는 [저장소 릴리스](https://github.com/minkwanchoi/ws-cwe-guide/releases)에서 아래 묶음 중 하나와 `SHA256SUMS.txt`를 받아, 출처 증명(`gh attestation verify <zip> --repo minkwanchoi/ws-cwe-guide`)과 해시를 확인한 뒤 반입한다.

| 묶음 | 내용 | 여는 법 |
|---|---|---|
| `ws-cwe-guide-offline-v{{VERSION}}.zip`(약 11 MB) | 이 사이트 전체(검색·탐색 포함)와 Excel 2종 | 압축을 풀고 `index.html`을 열거나 내부 웹서버에 그대로 올린다 |
| `ws-cwe-guide-single-v{{VERSION}}.zip`(약 2 MB) | 본문·부록·규칙별 해설을 담은 HTML 파일 하나, 지침 선택 도구·CWE 버전 비교 파일, Excel 2종 | `가이드(단일문서).html`을 연다. 찾기는 Ctrl+F, 인쇄·PDF 저장이 된다 |

원천 데이터(지침·태깅·근거 목록 요약)는 [저장소 `source/data`](https://github.com/minkwanchoi/ws-cwe-guide/tree/main/source/data)에 있다.
