# 출처와 이용 조건

이 가이드는 개인 연구자(minkwanchoi)가 교육·연구 목적으로 공개한 참고 자료다. 방위사업청·MITRE·행정안전부·한국인터넷진흥원이 발간·승인·검토하지 않았다. CWE™는 The MITRE Corporation의 상표이며, 이 가이드는 MITRE와 제휴 관계가 없다.

이 가이드는 아래 제3자 자료를 인용·요약하고 원문으로 연결한다. 각 자료의 권리는 원저작자에게 있으며, 이용 조건은 원문을 따른다.

## 제3자 자료

| 자료 | 이 가이드에서 쓰는 범위 | 조건·출처 |
|---|---|---|
| MITRE CWE 5.0 | CWE 번호·영문 제목, 뷰 구성, 규칙별 해설 페이지의 영문 원문(설명·영향·완화책·탐지 방법·관찰 사례·분류 대응·원문 예시), Excel 원문 시트, 원천 데이터 `cwe_original.json`·`cwe_original_extra.json`·`cwe_examples_original.json`·`cwe_197.json`·`cwe_mapping.json`, 그리고 원문의 비공식 한글 해설 | Copyright © 2006–2026, The MITRE Corporation. 이용 조건과 허락 문구 전문은 아래 'MITRE CWE 이용 허락 문구'에 있다. 한글 해설을 다시 쓸 때도 MITRE의 저작권 표시와 이용 허락 문구를 함께 실어야 한다 |
| CVE 기록 | CVE 번호와 링크, 규칙별 해설에 있는 CWE 관찰 사례의 설명 | Copyright © 1999-2026, The MITRE Corporation. CVE는 The MITRE Corporation의 상표다. [CVE 이용 조건](https://www.cve.org/Legal/TermsOfUse)에 따라 저작권 표시와 이용 허락 문구를 함께 싣는다(아래 전문) |
| Microsoft Learn 문서 | .NET 보안 규칙 94개의 제목 원문과 링크(부록 D-1, Excel) | Microsoft. 원천 저장소 dotnet/docs·MicrosoftDocs/cpp-docs·MicrosoftDocs/win32·MicrosoftDocs/visualstudio-docs는 [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)이다. 규칙 제목은 원문 그대로이고, 한글 요약과 CWE 대응은 이 가이드가 작성한 것이다(변경). 그 밖의 Microsoft 문서는 링크와 위치, 이 가이드가 쓴 한글 요약만 적는다 |
| Bandit | 규칙 번호·이름, 규칙이 붙인 CWE 번호와 링크(부록 D-2, Excel). 코드는 싣지 않는다 | PyCQA Bandit, [Apache License 2.0](https://github.com/PyCQA/bandit/blob/1.9.4/LICENSE) |
| 방위사업청 「무기체계 소프트웨어 개발 및 관리 매뉴얼」 제2024-6호 | 조항의 위치와 요지, 「보안약점 점검 목록」 44개의 CWE 번호, 본문의 짧은 인용 | 방위사업청 공개 자료. 원문 전재 없이 요지와 위치만 인용한다. 부록의 제안요청서(안) 견본처럼 복제·배포 제한 표기가 있는 부분은 싣지 않는다 |
| SEI CERT 코딩 표준(C·C++·Java) | 규칙 ID와 제목, 링크, 이 가이드가 쓴 한글 요약 | Carnegie Mellon University. [원천 저장소](https://github.com/cmu-sei/secure-coding-standards) 기준 표준은 CC BY 4.0, 코드 예시는 MIT다. CERT는 Carnegie Mellon University의 등록상표다 |
| MISRA C·C++, AUTOSAR C++14 | 규격 이름·판·규칙 번호, 링크 | 규칙 본문은 전재하지 않는다. MISRA와 MISRA C는 The MISRA Consortium Limited의 등록상표이고, AUTOSAR는 등록상표다. AUTOSAR 지침은 정보 목적의 무수정 복제만 허용하므로 링크와 규칙 번호만 쓴다 |
| NIST SP 800-218 (SSDF 1.1) | 실천 번호와 짧은 인용 | 미국 NIST 출판물 |
| 행정안전부·한국인터넷진흥원 가이드, 과학기술정보통신부·한국인터넷진흥원 Python 가이드 | 보안약점 항목명, 판·쪽 정보 | 판권면에 따라 무단 전재·복제하지 않고, 코드와 본문을 싣지 않으며, 출처를 밝혀 인용한다. Python 가이드는 판권면이 영리 목적 사용도 금하므로, 인용 부분의 출처는 과학기술정보통신부와 한국인터넷진흥원의 '파이썬 시큐어코딩 가이드'다. 이 인용 부분에는 MIT를 적용하지 않는다 |
| 오픈소스 프로젝트와 도구 문서(PX4, ArduPilot, NASA cFS·F´, FreeRTOS, C2000Ware, Xilinx embeddedsw, U-Boot, Yocto, GCC 등) | 태그로 고정한 파일 위치와 링크(원천 데이터 `evidence_*.json`, Excel '오픈소스근거' 시트, 부록 E). 원문 문장은 싣지 않는다 | 각 자료의 라이선스를 따른다. 인용한 판의 라이선스 파일 기준으로 다음을 확인했다(2026. 11. 1.). Apache-2.0: NASA OSAL·cFE·cFS·F´, CMSIS, Zephyr, NuttX, mcuboot, OpenSSL, atheris, pip-audit. MIT: FreeRTOS, sharpfuzz, coverlet, gitleaks. BSD: PX4, STM32 HAL. GPL-3.0: ArduPilot, MissionPlanner, MAVProxy, cppcheck. GPL-2.0: Linux, U-Boot. LGPL: pymavlink, ArduinoCore-avr(소스 머리말 기준). AGPL-3.0: Yamcs. 이중·복합: Mbed TLS(Apache-2.0·GPL-2.0), QGroundControl(Apache-2.0·GPLv3), PyInstaller, Xilinx embeddedsw, poky는 구성요소마다 다르다. C2000Ware는 저장소의 매니페스트를 따른다. 문서: GCC·Qt GFDL 1.3, Yocto CC BY-SA 2.0 UK, reproducible-builds.org CC BY-SA 4.0, MAVLink CC BY 4.0, avr-libc 수정 BSD, Python PSF-2.0, SLSA Community Specification License 1.0 |
| 그 밖의 도구·프로젝트 문서(MicroPython, .NET nanoFramework, MinGW-w64, Jenkins, Valgrind, Oracle Java 문서 등) | 공식 링크와 위치, 이 가이드가 한글로 요약한 내용 | 원문 문장을 싣지 않는다. 각 자료의 조건을 따른다 |
| 독점 벤더 문서(Texas Instruments, Microchip, AdaCore, Wind River) | 공식 원문 링크와 위치, 이 가이드가 한글로 요약한 내용 | 원문 문장을 싣지 않는다. 각 벤더의 권리와 조건을 따른다([TI 이용 약관](https://www.ti.com/legal/terms-conditions/terms-of-use.html), [Microchip 저작권 지침](https://www.microchip.com/en-us/about/legal-information/copyright)). 비공식 사본은 근거로 쓰지 않고 링크하지 않는다 |
| 국립국어원 우리말샘·표준국어대사전 | 용어 표기의 근거 링크(부록 F, `glossary.json`). 뜻풀이 문장은 싣지 않는다 | [CC BY-SA 2.0 KR](https://opendict.korean.go.kr/service/copyrightPolicy). 표준국어대사전도 [같은 조건](https://stdict.korean.go.kr/join/copyrightPolicy.do)이다. TTA 용어사전은 링크만 적는다 |
| 최민관·박다운·국승학(2019), 소프트웨어공학 소사이어티 논문지 28(1) | 개발환경 분류(표 7)와 시험 환경 논의의 인용 | 학술 인용 |

## 함께 배포하는 테마·글꼴

사이트판과 폐쇄망 사이트판은 Material for MkDocs 테마, lunr 검색, IBM Plex 글꼴, 아이콘을 함께 배포한다. 구성요소별 저작권 표시와 라이선스 전문은 사이트 최상위 폴더의 [THIRD-PARTY-NOTICES.txt](source/guide/THIRD-PARTY-NOTICES.txt)에 있다.

## 이 가이드의 라이선스

이 가이드의 원고·데이터·Excel·스크립트·예시 코드·지침 선택 도구는 작성자(minkwanchoi)가 [MIT 라이선스](LICENSE)로 공개한다. 교육·연구 목적으로 공개하지만 MIT는 이용 목적을 제한하지 않으므로 상업적 이용·수정·재배포도 허용된다. 조건은 저작권 표시와 허락 문구를 함께 싣는 것이고, 가이드는 어떤 보증도 없이 'AS IS'로 제공된다.

작성자가 권리를 갖지 않는 다음 자료는 MIT로 허락하지 않으며, 각 조건을 따른다.

1. MITRE CWE·CVE 원문: 위 파일과 해설 페이지의 영문 원문, Excel 원문 시트. 이 가이드가 쓴 한글 번역·요약(`cwe_ko_commentary.json`, Excel 한글 요지)은 작성자의 기여분만 MIT이고 2차적저작물이므로 MITRE 이용 조건이 함께 적용된다.
2. 본문의 짧은 인용(매뉴얼 문구, 논문 등): 원저작자의 권리에 속하며, 이 가이드는 교육·연구를 위해 출처를 밝혀 인용한다(저작권법 제28조·제37조). 재사용자는 각 원문의 조건을 직접 확인한다.
3. Microsoft Learn·SEI CERT 원문: 각각 위 조건을 따른다.
4. 함께 배포하는 테마·글꼴·아이콘: `assets/` 아래 자산(저장소에서는 `source/assets/vendor/`의 IBM Plex 글꼴과 검색 셰임 포함)과 `THIRD-PARTY-NOTICES.txt`의 구성요소. 글꼴은 SIL OFL 1.1이고 라이선스 전문은 글꼴 폴더의 `OFL.txt`에도 있다.

고친 판을 배포할 때는 원본과 구별되게 표시하고 공식 문서처럼 보이지 않게 해 주기를 요청한다(라이선스 조건은 아니다). 원본 여부는 저장소 릴리스의 SHA-256 해시로 확인한다.

## 상표

이 가이드에 나오는 제품·규격·기관 이름과 상표는 각 소유자의 것이며, 이름을 쓴 것은 설명을 위한 것으로 제휴나 보증을 뜻하지 않는다.

## MITRE CWE 이용 허락 문구

영문 원문은 MITRE CWE 5.0에서 가져왔다. Copyright © 2006–2026, The MITRE Corporation. CWE™와 CWE 로고는 The MITRE Corporation의 상표다. [CWE 이용 조건](https://cwe.mitre.org/about/termsofuse.html)(조회 2026. 10. 15.)은 복제본에 저작권 표시와 아래 이용 허락 문구를 함께 싣도록 정한다.

> CWE™ is free to use by any organization or individual for any research, development, and/or commercial purposes, per these CWE Terms of Use. Accordingly, The MITRE Corporation hereby grants you a non-exclusive, royalty-free license to use CWE for research, development, and commercial purposes. Any copy you make for such purposes is authorized on the condition that you reproduce MITRE’s copyright designation and this license in any such copy. CWE is a trademark of The MITRE Corporation.

원문은 'as is'로 제공된다(이용 조건의 DISCLAIMERS). 한글 해설은 이 가이드가 원문을 번역·요약한 것으로 MITRE가 검토하지 않았다.

## CVE 이용 허락 문구

Copyright © 1999-2026, The MITRE Corporation. [CVE 이용 조건](https://www.cve.org/Legal/TermsOfUse)(조회 2026. 11. 1.)의 문구는 다음과 같다.

> CVE Usage: MITRE hereby grants you a perpetual, worldwide, non-exclusive, no-charge, royalty-free, irrevocable copyright license to reproduce, prepare derivative works of, publicly display, publicly perform, sublicense, and distribute Common Vulnerabilities and Exposures (CVE™). Any copy you make for such purposes is authorized provided that you reproduce MITRE's copyright designation and this license in any such copy.
