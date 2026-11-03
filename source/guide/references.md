# 참고문헌

> **읽는 법.** 본문과 부록에서 인용한 자료를 유형별로 싣는다. 온라인 자료는 조회일(확인일)을 적고, 오픈소스는 인용한 릴리스 태그로 고정한다. 사례 근거의 파일·행 위치는 본문 사례 상자와 부록 E에 있다.

## 가. 규정·기준

1. 방위사업청. 「무기체계 소프트웨어 개발 및 관리 매뉴얼」. 방위사업청 매뉴얼 제2024-6호(2024.12.26. 개정), 발간등록번호 11-1690000-002028-10. 방위사업청 행정규칙 게시판 첨부(본문·부록·신구조문대비표), https://www.dapa.go.kr/dapa/rlm/rllawd/RlmNttList.do?menuSeq=3088&SelctgryId=6 (확인 2026. 10. 15.). 첨부 파일명은 '개정안'이고 PDF 생성일은 본문 2025. 1. 8., 부록 2025. 1. 7.이다. 인쇄 확정본과의 동일성은 확인하지 않았다.
2. 방위사업청. 「무기체계 소프트웨어 개발 및 관리 매뉴얼」 제2014-1호(2014.2.19. 제정), 제2016-4호(2016.7.13. 개정). 제2024-6호 표지의 제·개정 이력으로만 확인했다. 이 가이드의 근거는 현행 제2024-6호이며, 제2016-4호 내용은 논문(아래 15)의 기술을 연혁으로만 인용한다(원문은 확보하지 않기로 함, 2026. 10. 18.).
3. 방위사업청. 「무기체계 소프트웨어 개발 지원에 관한 규정」. 방위사업청 훈령 제948호(2026.2.10. 일부개정). 국가법령정보센터(확인 2026. 10. 15.).
4. MITRE. Common Weakness Enumeration(CWE) Version 5.0(2026. 10. 28.). https://cwe.mitre.org/ (XML 배포 파일 cwec_v5.0.xml에서 197개와 보조 항목의 원문을 추출, 확인 2026. 11. 2.). 추상화 수준(Pillar·Class·Base·Variant·Compound)의 뜻은 CWE Glossary(https://cwe.mitre.org/documents/glossary/index.html), 매핑 권고(Usage) 표지의 뜻은 CVE → CWE Mapping "Root Cause Mapping" Guidance(<https://cwe.mitre.org/documents/cwe_usage/guidance.html>)를 따랐다(2.8, 모두 조회 2026. 11. 2.). 항목별 추상화 수준·매핑 권고·상위 관계는 같은 파일의 Abstraction·Structure 속성, Mapping_Notes, Related_Weaknesses(View 1000 ChildOf)에서 옮겼다. 탐지 방법의 효과성 표기는 원문이 인용하는 SOAR [REF-1479]를, 수명주기 단계 열거값은 CWE 스키마 8.0(cwe_schema_v8.0.xsd, 조회 2026. 11. 2.)을 따랐다(2.2, 6.2).
5. 행정안전부·한국인터넷진흥원. 「전자정부 SW 개발·운영자를 위한 소프트웨어 개발보안 가이드」. 2021.11(판권면, 5차 개정). https://www.kisa.or.kr/post/fileDownload?menuSeq=2060204&postSeq=5&attachSeq=2&lang_type=KO (조회 2026. 10. 15.). KISA 게시 파일명의 날짜(2021.12.29)는 판 일자가 아니다. 행정안전부도 같은 판을 정책자료 참고자료 게시판(2021.11.30.)에 게시했다(https://www.mois.go.kr/frt/bbs/type001/commonSelectBoardArticle.do?bbsId=BBSMSTR_000000000015&nttId=88956 , 조회 2026. 10. 15.). 2026. 10. 15. 현재 KISA·행정안전부 게시판에 후속 판은 없다.
6. 행정안전부·한국인터넷진흥원. 「소프트웨어 보안약점 진단가이드」. 2021.11(판권면, 4차 개정). https://www.kisa.or.kr/post/fileDownload?menuSeq=2060204&postSeq=9&attachSeq=1&lang_type=KO (조회 2026. 10. 15.). 2026. 10. 15. 현재 KISA 가이드라인 게시판에 후속 판은 없다.
7. Souppaya, M., Scarfone, K., Dodson, D. NIST SP 800-218, Secure Software Development Framework (SSDF) Version 1.1: Recommendations for Mitigating the Risk of Software Vulnerabilities. NIST, 2022.2. DOI 10.6028/NIST.SP.800-218. https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-218.pdf (확인 2026. 10. 15.). 참고: SP 800-218 Rev. 1(SSDF Version 1.2)은 2025.12.17 공개 초안(Initial Public Draft)만 있다(https://csrc.nist.gov/pubs/sp/800/218/r1/ipd, 확인 2026. 10. 15.).
8. 한국인터넷진흥원(KISA). 암호모듈검증(KCMVP) 개요. https://seed.kisa.or.kr/kisa/kcmvp/EgovSummary.do (조회 2026. 10. 15.).

## 나. 코딩 표준

9. MISRA. MISRA C:2012, MISRA C:2023, MISRA C++:2008, MISRA C++:2023. 판은 매뉴얼 제2024-6호 부록 6(인쇄 6-2쪽)의 관련 표준 목록을 따른다. MISRA C++:2023은 2023. 10. 발행(https://misra.org.uk/product/misra-cpp2023/ , 조회 2026. 10. 15.). AUTOSAR C++ 지침 통합 계획(2017년 발표)은 MISRA 사이트(https://misra.org.uk/ , 조회 2026. 10. 15.)의 서술이고, 통합 공지는 MISRA 포럼 'MISRA C++ new version'(2021. 11. 30., https://forum.misra.org.uk/printthread.php?tid=1439), 상세 추적표를 일반적으로 제공하지 않는다는 답변은 MISRA 포럼 'Documentation of reasoning to keep/modify/drop AUTOSAR rules'(2024. 3. 8., https://forum.misra.org.uk/printthread.php?tid=1674), AUTOSAR 쪽 이관 서술은 AUTOSAR C++14 지침 R22-11 3장(<https://www.autosar.org/fileadmin/standards/R22-11/AP/AUTOSAR_RS_CPP14Guidelines.pdf>)이다. 본문의 규칙 번호(Rule 9.1·10.1·21.3·21.6, Dir 4.7·4.12 등)는 지침 근거 칸과 오픈소스 사례에서 확인한 것이다. 판 서지(판권면 'First published' 기준): MISRA C:2012 2013.3.18 발행, Amendment 1 2016.4, AMD1·TC1을 합친 3판 1차 개정 2019.2, Amendment 2 2020.2, Amendment 3 2022.10, Amendment 4 2023.3, MISRA C:2023 2023.4(AMD2~4와 TC2 반영), MISRA C++:2008 2008.6.5, MISRA C++:2023 2023.10(https://misra.org.uk/misra-c/ , https://misra.org.uk/misra-c-plus-plus/ , 조회 2026. 10. 15.). 매뉴얼 부록 6에 없는 MISRA C:2025(2025.3)는 이 가이드의 기준에 넣지 않았다. MISRA는 기술 정오표를 반영한 MISRA C++:2023 (TC1:2026)을 내면서 새 지침이 없어 MISRA C++:2023과 같은 것으로 본다고 밝혔다(https://misra.org.uk/misra-c2023-tc-update/ , 조회 2026. 10. 28.).
10. 매뉴얼 부록 6이 나열한 그 밖의 표준: Stroustrup, B., Sutter, H.(편). C++ Core Guidelines(계속 개정되는 문서, 조회 시 판 2026-06-14), https://isocpp.github.io/CppCoreGuidelines/CppCoreGuidelines ; Oracle. Code Conventions for the Java Programming Language(1999.4.20 최종 개정, 보관용 페이지), https://www.oracle.com/java/technologies/javase/codeconventions-contents.html ; Microsoft. Common C# code conventions, https://learn.microsoft.com/en-us/dotnet/csharp/fundamentals/coding-style/coding-conventions ; Microsoft. Framework Design Guidelines(Cwalina·Abrams 2판 기준), https://learn.microsoft.com/en-us/dotnet/standard/design-guidelines/ (모두 조회 2026. 10. 15.).
11. Software Engineering Institute(SEI), Carnegie Mellon University. SEI CERT C Coding Standard. https://cmu-sei.github.io/secure-coding-standards/sei-cert-c-coding-standard/ (조회 2026. 10. 15.). SEI CERT 코딩 표준은 옛 위키(wiki.sei.cmu.edu/confluence)에서 이 공식 사이트로 옮겨졌다(원천 저장소 https://github.com/cmu-sei/secure-coding-standards ).
12. SEI. SEI CERT C++ Coding Standard. https://cmu-sei.github.io/secure-coding-standards/sei-cert-cpp-coding-standard/ (조회 2026. 10. 15.).
13. SEI. SEI CERT Oracle Coding Standard for Java. https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/ (조회 2026. 10. 15.).
14. AUTOSAR. Guidelines for the use of the C++14 language in critical and safety-related systems. AUTOSAR AP Release 19-03. https://www.autosar.org/fileadmin/standards/R22-11/AP/AUTOSAR_RS_CPP14Guidelines.pdf (R22-11 폴더 게시본, 조회 2026. 10. 15.). 문서 12쪽 범위 절에 폐기(obsolete) 예정과 MISRA 이관을 적는다. 본문에서는 보충 근거로만 인용한다.

## 다. 논문

15. 최민관·박다운·국승학(2019). 「무기체계 소프트웨어 신뢰성 시험을 위한 효율적 시험 환경 구축 방안」(An Efficient Method of Test Environment Setup for Weapon System Software Reliability Test). 「소프트웨어공학 소사이어티 논문지」 제28권 제1호, 7–12쪽. 2016년 개정판 기준의 연혁·배경, 개발환경 예시(표 7), 망 분리 환경의 통합 시험 환경(4.3절) 인용.

## 라. 용어 근거(부록 F)

16. 국립국어원. 「표준국어대사전」, 「외래어 표기법」. https://stdict.korean.go.kr/, https://www.korean.go.kr/ (조회 2026. 10. 15.).
17. 한국정보통신기술협회(TTA). 「TTA 정보통신용어사전」. https://terms.tta.or.kr/ (조회 2026. 10. 15.).
18. 김항규·박태형(2023). 「SW명세서(SBOM) 도입 및 활성화 방안 연구」. 소프트웨어정책연구소 연구보고서 RE-137(2023.9.22 게시), https://spri.kr/posts/view/23644 ; 김항규(2022). 「SW공급망 강화를 위한 글로벌 동향」. 소프트웨어정책연구소(2022.4.28 게시), https://spri.kr/posts/view/23414 (조회 2026. 10. 15.).
19. 국내 학술지 용례(부록 F 근거 열): 정보보호학회지 「무기체계 소프트웨어 신뢰성 시험 현황 및 발전방향」(https://koreascience.or.kr/article/JAKO201807753431091.pdf); 한국산학기술학회논문지 「무기체계 성능개량사업 SW 신뢰성 시험 효율적 검증 방안 연구」(https://www.kais99.org/jkais/journal/Vol23No07/vol23no07p46.pdf), 「개발단계 무기체계의 소프트웨어 품질검증체계 연구」(https://kais99.org/jkais/journal/Vol24No04/vol24no04p42.pdf), 「소프트웨어 소스코드 구조분석 기반 무기체계 자동시험장비의 소프트웨어 유효성 검증방안 연구」(https://kais99.org/jkais/journal/Vol25no04/Vol25no04p14.pdf) (조회 2026. 10. 15.). 서지: 이태호·백옥현·김태현(2018), 「정보보호학회지」 28(6), 76–82쪽; 노시찬·김영길·손민정·김민혁(2022), 「한국산학기술학회논문지」 23(7), 389–398쪽, DOI 10.5762/KAIS.2022.23.7.389; 윤경환·박만춘·주진천·엄원용·오진우·윤재형·김종규(2023), 같은 학술지 24(4), 394–400쪽, DOI 10.5762/KAIS.2023.24.4.394; 오진우·윤경환·채신영·조한별·장지형(2024), 같은 학술지 25(4), 125–131쪽, DOI 10.5762/KAIS.2024.25.4.125.

## 마. 참조 오픈소스 프로젝트(릴리스 태그 고정, 확인 2026. 10. 15., 22·23·45의 LCS-12·LPY-11·13 근거는 2026. 10. 16.)

| 번호 | 프로젝트 | 고정 판(태그) | URL | 주요 인용 지침 |
|---|---|---|---|---|
| 21 | PX4-Autopilot | v1.17.0, v1.16.1 | https://github.com/PX4/PX4-Autopilot | PC-06, SBC-07, MCU-08, LCPP-09, GCC-02, WRW-04, LCPP-08(`.clang-tidy`·`Makefile`·`.github/workflows/clang-tidy.yml`, 6.2) |
| 22 | ArduPilot | Copter-4.7.1, Copter-4.5.7 | https://github.com/ArduPilot/ardupilot | MCU-02·03·08, BSP-01 |
| 23 | ArduPilot Mission Planner | MissionPlanner1.3.83 | https://github.com/ArduPilot/MissionPlanner | LCS-02·03·05·09·12 |
| 24 | MAVProxy / pymavlink | v1.8.75 / v2.4.50 | https://github.com/ArduPilot/MAVProxy, https://github.com/ArduPilot/pymavlink | LPY-03·04·06·11 |
| 25 | QGroundControl | v5.1.5 | https://github.com/mavlink/qgroundcontrol | PC-02·03·04·06, WIN-04, LNX-07 |
| 26 | NASA cFS(cFE·OSAL) | v7.0.1 | https://github.com/nasa/cFS, https://github.com/nasa/cFE, https://github.com/nasa/osal | LC-02·03·04·06·08, SBC-02, VXW-01·05, WRW-01·07, PSOS-01·05 |
| 27 | F Prime(F´) | v4.4.1 | https://github.com/nasa/fprime | LCPP-01·05·09, NET-CL-08 |
| 28 | Yamcs | yamcs-5.13.6 | https://github.com/yamcs/yamcs | LJ-02·07 |
| 29 | FreeRTOS-Kernel | V11.1.0, V11.3.1 | https://github.com/FreeRTOS/FreeRTOS-Kernel | FRT-01~05·07·08, LC-01·08, PSOS-03, CCS-08 |
| 30 | FreeRTOS-Plus-TCP | V4.4.1 | https://github.com/FreeRTOS/FreeRTOS-Plus-TCP | FRT-06 |
| 31 | FreeRTOS-LTS | 202406.05-LTS, 202604.01-LTS | https://github.com/FreeRTOS/FreeRTOS-LTS | FRT-09 |
| 32 | Zephyr | v4.2.0(문서 4.2.0) | https://github.com/zephyrproject-rtos/zephyr | GCC-01·05, OSS-01 |
| 33 | Apache NuttX | nuttx-13.1.0 | https://github.com/apache/nuttx | MCU-07, LCPP-02 |
| 34 | U-Boot | v2026.07(검증 부팅 문서 v2024.04) | https://github.com/u-boot/u-boot | SBC-01·09, LNX-03 |
| 35 | Yocto Project poky / 문서 / BitBake | yocto-5.0.4, 문서 5.0.4·5.2.4, BitBake 2.8 | https://github.com/yoctoproject/poky, https://docs.yoctoproject.org/ | LNX-01·03·04·09, SBC-04·10, OSS-01·07, NET-IN-05, NET-CL-04·09 |
| 36 | Linux kernel | v6.6 | https://github.com/torvalds/linux | LNX-08 |
| 37 | systemd(매뉴얼) | 254 | https://www.freedesktop.org/software/systemd/man/254/ | LNX-02 |
| 38 | MCUboot | v2.1.0 | https://github.com/mcu-tools/mcuboot | BM-03 |
| 39 | Arm CMSIS_5 / CMSIS_6 / CMSIS-DSP | 5.9.0 / v6.4.0 / v1.17.0 | https://github.com/ARM-software | BM-01·06, DSP-01·04·06·07 |
| 40 | STM32F4 HAL Driver | v1.8.3, v1.8.5 | https://github.com/STMicroelectronics/stm32f4xx_hal_driver | BM-03, BSP-02·03·04·07·08·10 |
| 41 | TI C2000Ware | REL_C2000Ware_v6.00.01.00, REL_C2000Ware_v26.02.00.00.LTS | https://github.com/TexasInstruments/c2000ware-core-sdk | DSP-02·05·09, CCS-02·03·07 |
| 42 | Xilinx embeddedsw | xilinx_v2026.1 | https://github.com/Xilinx/embeddedsw | SOC-01·02·04·07·08 |
| 43 | ArduinoCore-avr | 1.8.6, 1.8.7 | https://github.com/arduino/ArduinoCore-avr | MCU-05·09, AVR-04, BM-04 |
| 44 | cppcheck | 2.22.0(커밋 a436ca35) | https://github.com/cppcheck-opensource/cppcheck (구 danmar/cppcheck) | DSP-08, 6.2 `addons/misra.py`·`man/manual.md` |
| 45 | Mbed TLS / OpenSSL / zlib | v3.6.7 / openssl-3.6.5 / zlib.net(조회 2026. 10. 15.) | https://github.com/Mbed-TLS/mbedtls, https://github.com/openssl/openssl, https://zlib.net/ | OSS-03·04·05 |
| 46 | Gitleaks / pip-audit | v8.30.0 / v2.10.1 | https://github.com/gitleaks/gitleaks, https://github.com/pypa/pip-audit | NET-IN-04, LPY-09·13 |

## 바. 벤더·공식 문서(조회 2026. 10. 15.)

46. GNU Project. GCC 매뉴얼 13.2.0·14.2.0(일부 9.1.0·12.1.0·14.1.0), https://gcc.gnu.org/onlinedocs/gcc-13.2.0/ , https://gcc.gnu.org/onlinedocs/gcc-14.2.0/ ; GCC 14.2.0 소스 `configure.ac`(태그 releases/gcc-14.2.0).
47. GNU C Library. glibc 2.35 NEWS(태그 glibc-2.35). https://sourceware.org/git/?p=glibc.git
48. Microsoft Learn. MSVC 컴파일러·링커 옵션(`/GS`, `/sdl`, `/guard`, `/CETCOMPAT`, AddressSanitizer, C4996, CRT 보안 기능), Win32(DLL 보안, 파일 이름 규칙, `CryptProtectData`, `SetDefaultDllDirectories`, `GetFinalPathNameByHandle`, `CreateProcess`), Windows 보안·장치 관리, .NET·C#·NuGet(코드 분석 CA 규칙, BinaryFormatter 보안 가이드, Nullable 참조 형식, checked·unchecked, `dotnet list package`, Package Source Mapping, MSBuild 속성 `AnalysisLevel`, global.json(조회 2026. 10. 16.)), Visual Studio 오프라인 설치, 제품 수명주기 문서. https://learn.microsoft.com/
49. Texas Instruments. TMS320C28x Optimizing C/C++ Compiler User's Guide SPRU514AA(v25.11.0.LTS, 2026-03) 및 SPRU514Q; ARM Optimizing C/C++ Compiler User's Guide SPNU151W(v20.2.0.LTS, 2023-03); MSP430 Optimizing C/C++ Compiler User's Guide SLAU132Y(v21.6.0.LTS, 2021-06); TMS320C6000 Optimizing C/C++ Compiler User's Guide SPRUI04G(v8.5.x, 2025-08); TI Arm Clang Compiler Tools User's Guide 5.1.0.LTS; SYS/BIOS 6.53.02.00 API 문서. https://www.ti.com/ , https://software-dl.ti.com/
50. Microchip Technology. ATmega48A/PA/88A/PA/168A/PA/328/P 데이터시트 DS40002061A.
51. avr-libc 2.1.0 사용자 매뉴얼. https://www.nongnu.org/avr-libc/user-manual/
52. Wind River. TCP/IP Network Stack(IPnet, Urgent/11) 보안 공지. https://www.windriver.com/security/announcements/tcp-ip-network-stack-ipnet-urgent11
53. AdaCore. GNAT User's Guide Supplement for Cross Platforms 28.0w, VxWorks Topics. https://docs.adacore.com/
54. Python Software Foundation. Python 3.13 문서, Python 개발자 가이드 버전 표, PEP 602. https://docs.python.org/3.13/ , https://devguide.python.org/versions/ , https://peps.python.org/pep-0602/
55. PyCQA Bandit 1.9.4 문서(https://bandit.readthedocs.io/en/1.9.4/); Ruff 규칙 문서(https://docs.astral.sh/ruff/rules/ , T100 debugger는 조회 2026. 10. 16.); pip 문서 Secure installs·로컬 패키지 설치(https://pip.pypa.io/).
56. OpenJDK. JEP 290: Filter Incoming Serialization Data. https://openjdk.org/jeps/290
57. Find Security Bugs(https://find-sec-bugs.github.io/); OWASP Dependency-Check(https://jeremylong.github.io/DependencyCheck/); Valgrind 지원 플랫폼(https://valgrind.org/info/platforms.html); Linux man-pages `mkstemp`(https://man7.org/linux/man-pages/man3/mkstemp.3.html); Trivy·Grype 문서(근거 목록의 태그 고정 주소); LLVM libFuzzer(https://llvm.org/docs/LibFuzzer.html); Apache Struts 1 지원 종료 공지(https://struts.apache.org/struts1eol-announcement.html); OpenJDK JEP 181(https://openjdk.org/jeps/181)·JEP 411(https://openjdk.org/jeps/411)·JEP 486(https://openjdk.org/jeps/486); NIST SP 800-90B(https://csrc.nist.gov/pubs/sp/800/90/b/final); Arm Cortex-M3 Devices Generic User Guide DUI0552 CCR(DIV_0_TRP)(<https://developer.arm.com/documentation/dui0552/latest/>)(조회 2026. 11. 3.).
58. Jenkins. Access Control 문서. https://www.jenkins.io/doc/book/security/access-control/
59. Reproducible Builds. 정의·SOURCE_DATE_EPOCH·빌드 경로 문서. https://reproducible-builds.org/docs/
60. SLSA. v1.0 Provenance 사양. https://slsa.dev/spec/v1.0/provenance
61. 기타: MAVLink 개요(https://mavlink.io/en/about/overview.html), Qt 6.8 QProcess 문서(https://doc.qt.io/qt-6.8/qprocess.html), Linux man-pages getrandom(2)(https://man7.org/linux/man-pages/man2/getrandom.2.html), GNU GPL v3, Apache License 2.0.

## 사. 취약점(CVE) 레코드

62. CVE Program. 본문에서 인용한 CVE 레코드: CVE-2010-2965(VxWorks WDB), CVE-2018-16601(FreeRTOS+TCP), CVE-2019-12256(VxWorks IPnet), CVE-2020-10648(U-Boot), CVE-2021-31571·CVE-2021-43997(FreeRTOS), CVE-2021-44228(Apache Log4j2), CVE-2026-5476(NASA cFS), CVE-2026-32706·CVE-2026-32743(PX4-Autopilot), CVE-2026-55559(Yamcs). https://www.cve.org/ (조회 2026. 10. 15.). 부록 E에 인용한 나머지 CVE는 각 행에 ID로 적었다.

## 아. C#·Python 시험·유지보수 지침 보강 근거(조회 2026. 10. 16.~17.)

63. 과학기술정보통신부·한국인터넷진흥원. 「Python 시큐어코딩 가이드」. 2023.12(판권면: 인쇄·발행 2023년 12월). KISA 가이드라인 게시판 글(등록일 2022. 12. 29.)의 첨부 'Python_시큐어코딩_가이드(2023년_개정본).pdf'(확인 2026. 10. 17.). 게시판 등록일은 판 일자가 아니다. 제2장 제6절 2 '제거되지 않고 남은 디버그 코드'(인쇄 147쪽), 제2장 제7절 2 '취약한 API 사용' 다. 사후 관리(인쇄 160~161쪽). 규칙별 해설의 Python 예시(나쁜 예·좋은 예)는 이 KISA 가이드의 항목명과 쪽만 참고로 적고, 그 코드는 싣지 않는다(판권면의 이용 조건). https://www.kisa.or.kr/2060204/form?postSeq=13 — LPY-12·13
64. coverlet v10.1.0 README. https://github.com/coverlet-coverage/coverlet — LCS-11
65. SharpFuzz v2.2.0 README. https://github.com/Metalnem/sharpfuzz — LCS-12
66. Google. Atheris 3.0.0 README. https://github.com/google/atheris — LPY-11
67. PyInstaller v6.22.3 문서 `doc/operating-mode.rst`(Hiding the Source Code). https://github.com/pyinstaller/pyinstaller — LPY-12

## 자. 시큐어코딩 가이드(예시의 대응 항목·쪽만 연결)

68. 행정안전부. 「C 시큐어코딩 가이드」(3판)·「JAVA 시큐어코딩 가이드」(3판). 2012. 9.(개정 이력 기준). 규칙별 해설의 예시(나쁜 예·좋은 예)는 이 가이드의 항목명과 쪽만 적고 코드는 싣지 않는다(판권면의 무단 전재·복제 금지).

## 차. 언어와 운용 환경 조합 안내 근거(조회 2026. 10. 23.)

69. MicroPython v1.29.0 README(마이크로컨트롤러 지원 설명). https://github.com/micropython/micropython/blob/v1.29.0/README.md — 2.5 ②
70. .NET nanoFramework Home README(커밋 6235f8d, 마이크로컨트롤러용 C# 개발 설명). https://github.com/nanoframework/Home/blob/6235f8d444df34dfe3dbe6c2cbfa3bb912b99325/README.md — 2.5 ②
