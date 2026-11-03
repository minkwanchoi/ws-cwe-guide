# 제5장 구현 단계 지침

## 5.1 단계 목표·입력·산출물

구현 단계는 설계에서 정한 보호를 코드와 빌드 설정으로 옮기고, 언어 고유의 보안약점을 코딩규칙(coding rule)으로 막는 단계다. 매뉴얼 정적시험의 코딩규칙 검증은 「무기체계 소프트웨어 코딩규칙」(매뉴얼 부록 6)의 준수 여부를 보는 시험이고([표준] 매뉴얼 부록 7, 인쇄 7-10쪽), 정적시험은 개발 초기부터 수행하도록 되어 있다([표준] 매뉴얼 부록 7, 인쇄 7-5쪽). 따라서 코딩 표준과 빌드 설정은 구현을 시작하기 전에 정하고, 코드를 쓰는 동안 계속 점검한다. 매뉴얼은 단위시험도 구현 단계에 두고, 이 단계에서 신뢰성시험과 보안성시험을 지속적으로 수행해 결함을 사전에 제거하도록 한다([표준] 매뉴얼 제2024-6호 제2장 Ⅸ, 인쇄 57·59쪽).

**입력.** 설계 단계에서 낸 소프트웨어설계기술서(SDD)·인터페이스통제문서(ICD)의 필드 범위표, 자원 예산표, 오류 처리 정책서, 키 관리 설계서와 승인 알고리즘 목록, 구성요소 선정표와 SBOM 초안(제4장), 요구사항 분석 단계에서 정한 언어별 점검 기준표와 보안약점 적용성 판정(부록 G-4, 제3장), 환경 프로파일과 지침 선택 결과(부록 G-3)를 입력으로 쓴다.

**산출물.** 활동마다 '산출물' 항목에 적었다(5.2).

## 5.2 기준선 활동 I-01~I-10

구현 단계의 기준선 활동은 I-01~I-10의 10개다. I-10 호스트 동적 분석은 단위시험과 함께 한다(ID 접두어의 뜻은 1.4). 관리형 언어와 인터프리터 언어의 대응 활동은 5.5~5.7에 있다. '강화·대체 지침' 항목의 뜻은 2.3에 있다.

**매뉴얼 코딩규칙과의 관계.** I-01은 매뉴얼 부록 6이 정한 코딩규칙을 사업 코딩 표준으로 옮기는 활동이다. 관련 표준 목록은 1.3의 표에 있다. 체계·소프트웨어 특성과 운용환경에 가장 맞는 표준을 따르는 것이 원칙이며, 표준을 선정·조정할 때는 사유를 제시하고 사업관리회의에서 확정한다([표준] 매뉴얼 부록 6, 인쇄 6-2·6-3쪽).

매뉴얼 제2024-6호에는 적용 규칙 개수를 정한 서술이 없다. 규칙 수는 사업 코딩 표준에서 정하고, 시험확인서에는 "MISRA C:2012(AMD1) 총 xx개 규칙"처럼 적용한 규칙 수를 적는다([표준] 매뉴얼 부록 7, 인쇄 7-27쪽). SEI CERT 규칙과 AUTOSAR C++14는 부록 6 목록에 없으므로 사업 코딩 표준을 대신하지 않고 보충 근거로 쓴다.

### I-01 사업 코딩 표준 수립과 편차 관리 {#i-01}

*구현 · 기준선*

- 적용 조건: 항상(언어별 기준은 2.6)
- 대상 약점: CWE-658/659/660 전반
- 지침: 언어마다 매뉴얼 부록 6의 표준 하나를 골라 사업 코딩 표준으로 정하고, 조정한 규칙과 사유를 적는다. 편차는 규칙 번호·위치·사유·승인자를 대장에 기록하고, 정적 분석(static analysis) 도구의 억제 설정과 대장을 일치시킨다. 벤더 BSP(보드 지원 패키지)와 오픈소스처럼 규칙 전면 적용이 어려운 코드는 테일러링(tailoring) 문서에 제외 범위를 적되, CWE 점검과 컴파일러 경고 점검은 그 코드에도 유지한다.
- 산출물: 사업 코딩 표준, 편차 대장(매뉴얼 서식으로 낼 때는 부록 7 별첨 1-7의 코딩규칙점검 FA 사유서, 인쇄 7-22쪽), 테일러링 문서
- 근거: [표준] 매뉴얼 제2024-6호 부록 6 코딩규칙(관련 표준 인쇄 6-2쪽, 선정·조정 6-3쪽), MISRA C:2012/2023, MISRA C++:2023, SEI CERT C/C++/Java(보충) · SSDF PW.5
- 강화·대체 지침: (강화) BSP-08

### I-02 금지 함수·대체 API 지정과 컴파일 단계 차단 {#i-02}

*구현 · 기준선*

- 적용 조건: 언어 런타임(L1) = 네이티브-비안전
- 대상 약점: CWE-120, CWE-134, CWE-170, CWE-242, CWE-676
- 지침: `gets`·`strcpy`·`strcat`·`sprintf`처럼 경계를 검사하지 않는 함수를 금지 목록에 올리고, 길이 인자를 받는 대체 함수를 지정한다. 금지 함수 사용은 빌드에서 막는다(`#pragma GCC poison`, MSVC 폐기 경고 C4996을 끄지 않음 등). 벤더 라이브러리와 레거시 코드에도 같은 목록으로 사용 여부를 점검한다.
- 산출물: 금지 함수·대체 API 목록, 차단 설정
- 근거: [CWE] CWE-676 완화책(Build and Compilation·Implementation) · [표준] SEI CERT STR31-C·STR32-C, MISRA C:2012 Rule 21.6
- 강화·대체 지침: (강화) MSVC-04, LC-04

### I-03 신뢰 경계 입력 검증 {#i-03}

*구현 · 기준선*

- 적용 조건: 항상
- 대상 약점: CWE-119, CWE-125, CWE-129, CWE-134, CWE-787 / 보조 항목 CWE-611
- 지침: D-02에서 정한 검증 지점에서 허용목록(allowlist) 방식으로 길이·범위·형식·열거값을 검사한다. 검증을 통과한 데이터만 내부로 넘기고, 실패하면 설계에서 정한 안전 상태로 전이한다. 프레임 길이 필드와 실제 수신 길이가 다르면 버린다. XML로 받는 입력(ICD 정의·임무 계획·설정 파일)은 외부 개체(DTD) 해석을 끈 해석기로 읽는다.
- 산출물: 입력 검증 함수, 검증 실패 처리 코드
- 근거: [CWE] CWE-129 완화책(Architecture and Design·Implementation: Input Validation), CWE-120 완화책(Implementation: Input Validation), CWE-611 완화책(Implementation·System Configuration) · [표준] SEI CERT ARR30-C, 행정안전부·KISA 「소프트웨어 개발보안 가이드」(2021) 구현단계 '부적절한 XML 외부 개체 참조'(인쇄 170쪽)
- 강화·대체 지침: (강화) SBC-05, SOC-03, PSOS-02, FRT-06, BM-05, LC-02, LPY-07

### I-04 명령·질의·경로·자원 식별자 무력화(매개변수화) {#i-04}

*구현 · 기준선*

- 적용 조건: 사용 기술 체크리스트에 OS 명령 실행·DB·파일 경로·자원 식별자 지정이 있거나 외부 입력을 해석할 때(외부 입력은 자원 식별자를 정할 수 있다)
- 대상 약점: CWE-22, CWE-59, CWE-78, CWE-89, CWE-99
- 지침: 외부 프로세스는 셸을 거치지 않고 인자 배열로 호출한다. DB는 매개변수화 질의만 쓴다. 파일 경로는 정규화한 뒤 허용 디렉터리 안인지 확인하고, 포트·장치 번호 같은 자원 식별자는 고정 매핑 테이블로 바꾼다.
- 산출물: 명령·질의·경로 처리 래퍼
- 근거: [CWE] CWE-78·89 완화책(Architecture and Design: Parameterization) · [표준] SEI CERT ENV33-C, IDS00-J
- 강화·대체 지침: (강화) PC-05, WIN-05, LNX-05, MSVC-06, LJ-04, LPY-05, LPY-06

### I-05 정수·포인터·메모리 안전 코딩 {#i-05}

*구현 · 기준선*

- 적용 조건: 언어 런타임(L1) = 네이티브-비안전(관리형 언어는 5.5~5.6)
- 대상 약점: CWE-190, CWE-191, CWE-369, CWE-415, CWE-416, CWE-457, CWE-467, CWE-469, CWE-476
- 지침: 크기·인덱스 계산 전에 오버플로와 0으로 나누기를 검사한다. 모든 변수는 선언할 때 초기화하고, 해제한 메모리는 다시 쓰지 않는다. 해제 후 포인터 NULL 설정은 심층 방어로 더한다. 포인터 크기·`sizeof` 결과·정수 폭을 플랫폼마다 같다고 가정하지 않는다.
- 산출물: 정수 검사 함수, 메모리 소유권 규칙을 따른 코드
- 근거: [CWE] CWE-190 완화책(Implementation: Input Validation, Compilation or Build Hardening) · [표준] SEI CERT INT30-C·INT32-C·MEM30-C
- 강화·대체 지침: (강화) MCU-04, MCU-06, DSP-04, DSP-05, VXW-06, PSOS-04, BM-05, CCS-01, AVR-03, LC-03, LC-05, LC-07, LCPP-01, LCPP-04, LCPP-05, LCPP-06

### I-06 오류·반환값·예외 처리 {#i-06}

*구현 · 기준선*

- 적용 조건: 항상
- 대상 약점: CWE-209, CWE-390, CWE-476, CWE-755
- 지침: 오류 정보를 돌려주는 함수의 반환값은 모두 검사하고, 버리려면 `(void)` 캐스트처럼 의도를 드러낸다. 예외를 쓰는 언어에서는 구체적인 예외만 잡고 빈 `catch`를 금지한다. 오류 메시지에 내부 경로·주소·비밀을 넣지 않는다.
- 산출물: 반환값 검사 규칙을 따른 코드, 예외 처리 규약
- 근거: [CWE] CWE-390 완화책(Implementation) · [표준] MISRA C:2012 Dir 4.7, SEI CERT ERR33-C
- 강화·대체 지침: (강화) PSOS-03, BSP-04, LC-06, LCS-08, LJ-05, LPY-08

### I-07 동시성·공유자원 보호 {#i-07}

*구현 · 기준선*

- 적용 조건: 항상
- 대상 약점: CWE-362, CWE-364, CWE-366, CWE-367, CWE-479
- 지침: 공유 자원은 상호배제나 원자 연산으로 보호하고 락 획득 순서를 문서화한다. ISR(인터럽트 서비스 루틴)과 공유하는 변수는 `volatile`로 선언한다. `volatile`은 원자성을 주지 않으므로, 레지스터 폭보다 큰 데이터와 읽기·수정·쓰기 연산은 인터럽트를 막은 임계구역(critical section)이나 원자 연산으로 보호한다. ISR에서는 블로킹 호출을 하지 않는다. RTOS(실시간 운영체제)·베어메탈(bare-metal) 환경의 ISR 공유변수 지침은 강화 지침 MCU-05·BM-04에 있다.
- 산출물: 공유 자원 목록과 보호 수단, 락 순서 문서
- 근거: [CWE] CWE-362 완화책(Architecture and Design·Implementation) · [표준] SEI CERT CON 계열
- 강화·대체 지침: (강화) SBC-06, MCU-05, VXW-05, PSOS-05, FRT-04, FRT-05, BM-02, BM-04, WRW-07, CCS-07, AVR-07, LCPP-07, LJ-06

### I-08 컴파일러 경고·빌드 하드닝 {#i-08}

*구현 · 기준선*

- 적용 조건: 항상(수단은 컴파일러 보호 기능 지원(L2)에 따라 대체)
- 대상 약점: CWE-14, CWE-119, CWE-120, CWE-121, CWE-134, CWE-733, CWE-628
- 지침: 타깃 컴파일러의 최대 경고 수준에서 경고 0건을 빌드 통과 조건으로 둔다. 컴파일러 보호 기능이 완전하면 운용 빌드 기본값으로 다음을 쓴다. GCC는 `-fstack-protector-strong`, `-D_FORTIFY_SOURCE=2` 이상(`-O1` 이상 최적화가 필요하므로 `-O0` 디버그 빌드는 제외, GCC 12 이상이면서 glibc 2.35 이상이면 3), `-fPIE -pie`, `-Wl,-z,relro,-z,now`를 쓴다. MSVC는 `/GS`가 기본으로 켜져 있으므로 `/GS-`로 끄지 않았는지 점검한다. `/guard:cf`는 컴파일러와 링커(`/GUARD:CF`)에 모두 지정하고 `/DYNAMICBASE` `/NXCOMPAT`를 링크 옵션으로 명시한다. 지원하지 않는 플래그가 조용히 빠지지 않도록 빌드에서 지원 여부를 검사한다. 보호 기능이 부분 지원이거나 없으면 8.1의 대체 활동(MPU(메모리 보호 장치) 영역 보호, 스택 가드·스택 페인팅(stack painting), trap 모드 UBSan, 정적 분석 강화)으로 바꾸고 "대체됨"으로 기록한다.
- 산출물: 빌드 설정 기준, 플래그 지원 검사 결과, 대체 통제 기록
- 근거: [CWE] CWE-119·120 완화책(Build and Compilation·Operation: Environment Hardening) · [표준] SSDF PW.6 · [사례] 사례 상자 5-1
- 강화·대체 지침: (강화) PC-04, WIN-04, LNX-04, WRW-03, WRW-04, CCS-04, MSVC-03, MSVC-05, AVR-04, GCC-01, GCC-02, GCC-03, GCC-04, GCC-07, LC-08 / (대체) WRW-05, CCS-05, AVR-05, GCC-05

> **사례 상자 5-1 — 빌드 하드닝과 경고 0건을 빌드에 고정한 사례**
> 이 사례는 지침이 실제 임베디드 코드에 쓰인 예다. 무기체계 적합성을 입증하지 않는다.
>
> - [사례·확인] (PC-04 → I-08) QGroundControl v5.1.5, `cmake/modules/Hardening.cmake:5` — 비디버그 빌드에서 컴파일러·링커의 플래그 지원 여부를 검사한 뒤 MSVC는 `/guard:cf`·`/DYNAMICBASE`·`/NXCOMPAT`, GCC 계열은 `-D_FORTIFY_SOURCE=3`·`-fstack-protector-strong`·`-Wl,-z,relro`·`-Wl,-z,now`를 적용한다. (확인 2026. 10. 15.)
> - [사례·확인] (LNX-04 → I-08) Yocto Project poky yocto-5.0.4, `meta/conf/distro/include/security_flags.inc:11-31` — 보안 플래그를 기본값으로 정의하고 `_FORTIFY_SOURCE`는 `-O1` 이상에서만 켠다. 같은 파일 머리 주석(1~4행)은 일부 레시피가 플래그를 쓰지 못해 예외 목록을 유지한다고 밝힌다. (확인 2026. 10. 15.)
> - [사례·확인] (LC-08 → I-08) NASA cFS v7.0.1(cFE v7.0.1), `cmake/sample_defs/arch_build_custom.cmake:29-32` — 샘플 빌드에 `-std=c99 -pedantic -Wall -Werror`를 적용. (확인 2026. 10. 15.)

### I-09 코드 리뷰·상시 정적 분석 {#i-09}

*구현 · 기준선*

- 적용 조건: 항상
- 대상 약점: 보안약점 점검 목록 44개 중 정적 분석 탐지 대상(43개, 6.1)
- 지침: 커밋이나 빌드마다 정적 분석을 돌리고, 새로 생긴 경고를 그 변경에서 처리한다. 정적 분석이 잡지 못하는 항목(설계 의도, 권한 검사 누락, 편차의 타당성)은 코드 리뷰 체크리스트로 본다. 도구가 지원하지 않거나 제외한 규칙은 목록으로 남겨 코드 리뷰로 보완한다.
- 산출물: 정적 분석 결과 이력, 코드 리뷰 기록
- 근거: [CWE] 탐지 방법 Automated Static Analysis, Manual Static Analysis · [표준] SSDF PW.7
- 강화·대체 지침: 없음

### I-10 호스트(타깃 외) 동적 분석 {#i-10}

*구현 · 기준선*

- 적용 조건: 타깃 외(호스트) 빌드(L3) = 가능
- 대상 약점: CWE-119, CWE-125, CWE-190, CWE-415, CWE-416, CWE-457, CWE-787
- 지침: 시험 빌드에 ASan·UBSan을 켜고 단위시험을 돌린다(통합 및 시험 단계에서도 같은 빌드를 쓸 수 있다). 공유 자원이 있는 코드는 TSan으로 따로 돌린다(ASan과 TSan은 함께 쓸 수 없다). MSVC는 ASan만 있고(x86·x64) UBSan이 없으므로 정수·미정의 동작은 정적 분석과 오버플로 검사 산술 라이브러리(예: SafeInt 라이브러리)로 보완한다. 베어메탈(bare-metal) 타깃은 런타임이 없으므로 trap 모드 UBSan(`-fsanitize-trap`)을 시험 빌드에 쓰는 방안을 검토한다.
- 산출물: 새니타이저 시험 결과(소프트웨어단위시험결과에 포함), 호스트·타깃 빌드 차이 목록(자료형 크기 `int`·`char` 포함)
- 근거: [CWE] CWE-415·416 탐지 방법(Automated Dynamic Analysis) · [표준] 매뉴얼 제2024-6호 제2장 Ⅸ(단위시험, 인쇄 57·59쪽), SSDF PW.8, GCC 14.2.0 매뉴얼 Instrumentation Options(조회 2026. 10. 15.)
- 강화·대체 지침: (강화) PC-06, SBC-07, MCU-08, GCC-08, LC-09, LCPP-09 / (대체) WRW-09, MSVC-08
- C++는 호스트 시험의 예외·RTTI·최적화 옵션을 타깃 빌드와 맞추거나, 다르면 호스트·타깃 빌드 차이 목록에 적는다(LCPP-09).

**단위시험 수준의 호스트 동적 분석(I-10).** 새니타이저(sanitizer)는 실행 중에 메모리 오류를 바로 검출하지만, 대부분 MMU(메모리 관리 장치)와 런타임 라이브러리가 있는 호스트에서만 돈다. 그래서 하드웨어 의존부를 떼어 낸 코드를 호스트에서 새니타이저·단위시험(unit test)·퍼징으로 먼저 거르고, 요구사항 기반 코드 실행률은 타깃에서 따로 잰다(LC-09, LCPP-09, MCU-08).

호스트와 타깃의 빌드 옵션이 다를 수 있으므로 그 차이 목록을 소프트웨어단위시험결과에 남기고, 통합 및 시험 단계에서 호스트 결과를 쓰면 STD의 차이 분석에 옮긴다(6.3). 예를 들어 PX4는 RTTI 옵션을 SITL(호스트)과 타깃 빌드에서 다르게 적용한다(사례: PX4-Autopilot v1.17.0, `cmake/px4_add_common_flags.cmake:165-167`, 확인 2026. 10. 15.).

> **사례 상자 5-2 — 호스트 보조 시험을 빌드에 넣은 오픈소스 사례**
> 이 사례는 지침이 실제 임베디드 코드에 쓰인 예다. 무기체계 적합성을 입증하지 않는다.
>
> - [사례·확인] (LCPP-09 → I-10) F´(F Prime) v4.4.1, `cmake/options.cmake:255,259` — `ENABLE_SANITIZER_ADDRESS`의 기본값을 `BUILD_TESTING` 값으로 정해 시험 빌드에서 AddressSanitizer가 기본으로 켜진다. (확인 2026. 10. 15.)
> - [사례·확인] (MCU-08 → I-10) ArduPilot Copter-4.7.1, `Tools/ardupilotwaf/boards.py:858-859,879` — SITL 빌드에서 `--ubsan`이면 `-fsanitize=undefined`와 `-fsanitize=float-cast-overflow`를, clang++의 `--asan`이면 `-fsanitize=address`를 추가한다. (확인 2026. 10. 15.)
> - [사례·확인] (SBC-07 → I-10) PX4-Autopilot v1.17.0, `docs/en/debug/simulation_debugging.md:7,11` — 호스트에서 `PX4_ASAN=1 make px4_sitl jmavsim`으로 Clang AddressSanitizer 빌드를 해 정렬 오류·세그먼트 오류 같은 메모리 결함을 찾는 방법을 제시. 같은 판 `docs/en/test_and_ci/fuzz_tests.md`(CI 절)는 퍼징 시험이 풀 리퀘스트마다 CI의 단위시험에 포함되고 main 브랜치에서는 매일 15분 더 돈다고 밝힌다. (확인 2026. 10. 15.)
> - [사례·확인] (PC-06 → I-10) QGroundControl v5.1.5, `cmake/modules/Sanitizers.cmake`(`QGC_ENABLE_ASAN`·`QGC_ENABLE_UBSAN` 블록) — CMake 옵션으로 AddressSanitizer·UBSan 빌드를 켠다. PX4-Autopilot v1.17.0 `docs/en/test_and_ci/fuzz_tests.md:7`는 퍼징 도구가 비정상 종료·단언 위반을 일으키는 입력을 찾을 때 Address Sanitizer가 자동으로 켜진다고 설명한다. (확인 2026. 10. 15.)

## 5.3 C 지침(CWE-658)

C는 메모리와 정수를 개발자가 직접 다루므로 CWE-119 계열 결함에 가장 취약하다. CWE-658(C) 뷰는 103개이고, 이 중 보안약점 점검 목록 44개에 드는 항목이 15개다(CWE-119·134·170·190·415·416·457·467·469·476·495·496·562·587·676). 미정의·구현 정의 동작이 컴파일러와 타깃(MCU·DSP)마다 다르게 드러나는 점도 C의 특징이다.

`memset_s`·`memcpy_s`(C11 부속서 K의 선택 사항), `explicit_bzero`·`strlcpy`는 C 표준의 필수 함수가 아니므로 대상 C 라이브러리의 지원을 확인하고, 없으면 volatile 소거 루틴이나 자체 경계 래퍼를 쓴다. 아래 표는 CWE-658의 주요 묶음과 구현 지침, 규칙 근거를 정리한 것이다. 항목별 지침은 각 CWE의 규칙별 해설과 C 규칙에 있고, 보안약점 점검 목록 44개는 부록 A에도 한 표로 있다. [근거] CWE 5.0 원문(CWE-658 구성원), 언어 환경 지침 LC-01~10(부록 C), 부록 A 구현(C/C++) 열

| 묶음(위험) | 대표 보안약점 | 구현 지침 | 규칙·도구 근거 | 지침 ID |
|---|---|---|---|---|
| 메모리 경계 | CWE-119·120·121·122·124·125·126·127·129·131·170·786·787·788·805·806·823 | 모든 복사·인덱스 접근 전에 길이를 대상 버퍼 크기와 비교한다. 길이 인자를 받는 함수를 쓰고 `snprintf` 반환값과 널 종료를 확인한다. 종단 문자가 없는 수신 프레임은 고정 길이로 처리한 뒤 종단을 붙인다. | [표준] CERT ARR30-C·STR31-C·STR32-C, MISRA C:2012 Rule 21.6 | LC-02, LC-04 |
| 정수·자료형 | CWE-128·190·191·192·193·194·195·196·197·680·681·839·1335 | 크기·인덱스 계산 전에 오버플로를 검사한다. 부호 있음·없음 혼용 비교와 암묵적 축소 변환을 금지한다. 고정폭 정수형(`stdint.h`)만 쓴다. | [표준] CERT INT30-C·INT32-C, MISRA C:2012 Rule 10.1~10.8·12.4, Dir 4.6 | LC-03, LC-05 |
| 포인터·메모리 수명 | CWE-401·415·416·457·466·467·468·469·476·562·587·588·590·690·761·762·763·822·824·825·911·1341 | 선언할 때 초기화하고, 해제 후 포인터 NULL 설정은 심층 방어로 더한다. 지역 변수 주소를 반환하거나 전역에 저장하지 않는다. NULL을 반환할 수 있는 함수의 결과는 역참조 전에 검사한다. 고정 주소 레지스터 접근은 HAL(하드웨어 추상화 계층)에만 두고 편차로 기록한다. | [표준] MISRA C:2012 Rule 9.1·18.6, Dir 4.7·4.11, Rule 11.4, CERT DCL30-C·MEM30-C·MEM01-C | LC-06, LC-07, MCU-06 |
| 포맷 스트링·위험 함수 | CWE-134·242·474·676·785 | `printf`류 포맷 인자는 리터럴로 고정하고, 금지 함수는 빌드에서 막는다(I-02). | [표준] CERT FIO30-C | LC-04, LC-06 |
| 동시성·시그널 | CWE-362·364·366·479·558·663·689·828 | 공유 자원은 상호배제로 보호한다. 시그널 핸들러와 ISR에서는 재진입 가능하고 비동기 안전한 함수만 쓴다. | [표준] SEI CERT CON 계열 | I-07, MCU-05, BM-04 |
| 코드 품질·컴파일러 | CWE-14·478·480·481·482·483·484·733·768·783 | 대입·비교 혼동, 중괄호 누락, `switch`의 `break`·`default` 누락을 규칙으로 막는다. 비밀을 지우는 코드가 최적화로 사라지지 않게 하고, 소스코드와 운용 빌드 바이너리를 대조해 확인한다(T-08). | [CWE] CWE-14 완화책(Implementation·Build and Compilation) · CWE-733은 상위 CWE-710 완화책 상속(2.7 규칙 1) | I-08, T-08 |
| 시스템 자원 | CWE-243·403·560·781·782·789·910·1325 | chroot·umask·파일 디스크립터·IOCTL 항목은 범용 OS를 전제로 한다. OS 유형이 RTOS·베어메탈이면 적용성 판정에서 근거와 함께 비해당 후보로 본다. 할당 크기는 상한을 검사한다. | [CWE] 완화책이 있는 항목은 그 완화책, CWE-243은 상위 CWE-573, CWE-910은 상위 CWE-666 상속 · [표준] CWE-403은 SEI CERT FIO42-C(2.7) · 판정은 2.5 ⑥ | D-07 |

C 뷰에만 있는 보안약점은 14개다. CWE-190(보안약점 점검 목록)과 CWE-193·403·474·560·590·663·681·685·688·689·761·768·828이다. 이들은 C++ 뷰에 없지만 C++ 코드에도 같은 결함이 생길 수 있으므로, C와 C++를 함께 쓰는 과제는 이 14개도 C++ 코드의 점검 범위에 넣는다. [보완]

비표준 자료형 타깃에서는 정수 지침을 강화한다. 자료형 모델(H5)이 비표준이면(AVR의 16비트 `int`, C28x의 16비트 `char`) 정수 승격과 `sizeof` 결과가 PC와 다르다. 바이트 단위 직렬화는 마스크·시프트로 명시하고, `sizeof` 결과를 바이트 수로 가정하지 않는다(MCU-04, DSP-05, CCS-01, AVR-03 → I-05 강화). 정적 분석 도구에도 같은 자료형 설정을 넣는다(DSP-08, 6.2).

## 5.4 C++ 보완 지침(CWE-659)

C++ 뷰에만 있는 보안약점은 없고 나머지는 C·Java 뷰와 겹친다(2.1). 보안약점 점검 목록 44개 중에서는 14개가 C++ 뷰에 든다. 따라서 C++ 코드에는 5.3의 C 지침을 그대로 상속해 적용한다.

C++의 고유 위험인 객체 수명, 예외 안전성, 캐스트, 반복자 무효화는 CWE 뷰가 다루지 않으므로 매뉴얼 부록 6의 MISRA-C++ 2008·2023과 C++ Core Guidelines로 다루고, SEI CERT C++와 AUTOSAR C++14를 보충 근거로 쓴다. AUTOSAR C++14의 지위와 MISRA C++:2023 통합 범위는 1.3에 있고, 규칙 대응은 과제가 정한다(LCPP-08).

대표 보안약점 칸의 '—'는 CWE 뷰가 다루지 않는 C++ 고유 위험이다.

| 묶음(위험) | 대표 보안약점 | 구현 지침 | 규칙·도구 근거 | 지침 ID |
|---|---|---|---|---|
| 소유권·수명 | — | raw `new`/`delete`를 금지하고 `unique_ptr` 등 RAII 래퍼로 수명을 관리한다. 동적 할당 금지 과제는 placement new와 고정 풀로 제한한다. | [표준] AUTOSAR C++14 A18-5-2, MISRA C++:2008 18-4-1 | LCPP-01(→I-05) |
| 예외 정책 | CWE-755 | 예외를 쓰면 소멸자를 `noexcept`로 하고 최상위 핸들러를 둔다. 쓰지 않으면 모든 반환 코드 검사를 정적 분석으로 강제한다. | [표준] MISRA C++:2008 15장 · [보완] (CWE-755 원문에 완화책 없음, 2.7 규칙 3) | LCPP-02(→D-08) |
| 다형·복사 | — | 다형 기반 클래스는 가상 소멸자를 두고 복사·이동을 `delete`해 슬라이싱을 막는다. 생성자·소멸자에서 가상 함수를 부르지 않는다. | [표준] MISRA C++:2008 12-1-1·12-8-2 | LCPP-03 |
| 포인터 산술 | — | C 배열·포인터 산술 대신 `std::array`, 범위 검사 접근(`at`), span 계열 뷰를 쓴다. `string_view`·span은 원본 수명 안에서만 보관한다. | [표준] MISRA C++:2008 5-0-15·5-0-16, CERT CTR50-CPP | LCPP-04(→I-05) |
| 캐스트 | — | C 스타일 캐스트와 `const_cast`를 금지하고 `reinterpret_cast`는 HAL의 한정된 위치에만 허용한다. | [표준] MISRA C++:2008 5-2-4·5-2-5 | LCPP-05(→I-05) |
| 반복자·참조 무효화 | — | 컨테이너를 수정하는 동안 보관한 반복자·참조·포인터를 다시 쓰지 않는다. 지역 객체 참조를 반환하거나 참조 캡처 람다를 비동기로 넘기지 않는다. | [표준] CERT CTR51-CPP·EXP54-CPP · [사례] QGroundControl v5.1.5(부록 E) | LCPP-06(→I-05) |
| 동시성·초기화 순서 | — | 공유 데이터는 `std::lock_guard` 같은 RAII 잠금으로 보호하고, 전역·정적 객체의 초기화 순서에 기대지 않는다. | [표준] CERT CON50-CPP·CON51-CPP·DCL56-CPP | LCPP-07(→I-07) |

**Java 뷰와 겹치는 9개.** 예외 처리 항목(CWE-248 처리되지 않은 예외, CWE-396·397 일반 예외에 대한 catch·throws 선언)은 LCPP-02의 예외 정책으로 다룬다. 클래스 설계 항목(CWE-493·498·500·543·766·767)은 공개 필드를 두지 않고 접근 함수를 거치게 하며, 다중 스레드 싱글톤은 동기화된 초기화를 쓰는 규칙으로 다룬다. 이 9개는 C에는 없으므로 C 지침이 아니라 이 절에서 챙긴다.

## 5.5 Java 지침(CWE-660)

Java는 JVM이 메모리 안전성을 주므로 위험이 역직렬화(deserialization), 삽입(injection), 예외 처리, 가변 객체 노출, 동시성으로 옮겨 간다. CWE-660(Java) 뷰는 84개이고, 그중 보안약점 점검 목록 44개에 드는 항목은 4개다(CWE-209·476·495·496). Java 뷰에만 있는 항목 57개 중 56개가 보안약점 점검 목록 밖이며, 이 56개는 성격이 뚜렷하게 둘로 나뉜다.

**① 웹·엔터프라이즈 실행 환경 전제 항목 30개(비해당 후보).** 이 항목들은 서블릿·EJB·Struts·J2EE 컨테이너나 표현 언어를 쓸 때만 생긴다. 프로젝트가 쓰는 프레임워크·API 목록과 대조해(LJ-01), 해당 기술이 없으면 '비해당'으로 판정하고 사유를 부록 G-4에 남긴다(2.5 ⑥). 지상 지원 소프트웨어처럼 실제로 서블릿·EJB를 쓰는 구성이면 '해당'으로 판정하고 행정안전부·KISA 「소프트웨어 개발보안 가이드」와 SEI CERT Java 규칙으로 다룬다.

묶음별로는 J2EE 설정 오류 6개(CWE-5·6·7·8·9·555), Struts 10개(CWE-102~110·608), J2EE 나쁜 관행 5개(CWE-245·246·382·383·579), EJB 나쁜 관행 5개(CWE-574~578), 서블릿 2개(CWE-536·600), J2EE 프레임워크 1개(CWE-594), 표현 언어(EL) 삽입 1개(CWE-917)다. 전체 목록은 부록 G-4-1 ②와 부록 B에 있다.

템플릿 엔진 삽입(CWE-1336)은 웹에 한정되지 않으므로 이 30개에 넣지 않고, 템플릿 엔진을 쓰는지로 따로 판정한다(2.1 각주). 비해당으로 판정한 항목도 목록에서 지우지 않는다. 사용 기술이 바뀌면 다시 판정한다(M-01).

**② 일반 Java 항목 26개(기본적으로 해당).** 웹 컨테이너와 관계없이 생기는 항목들이다. C·C++ 뷰와 공유하는 항목(정수 변환, 경쟁조건(race condition), 가변 객체 전달·반환 등)과 함께 다음 지침으로 다룬다. 표 끝의 XML 해석 행은 197개 밖의 보조 항목(부록 A-3)이다.

| 묶음(위험) | 대표 보안약점 | 구현 지침 | 규칙·도구 근거 | 지침 ID |
|---|---|---|---|---|
| 역직렬화·동적 코드 | CWE-502·470·95 | 외부 입력을 `ObjectInputStream`으로 직접 읽지 않고, 불가피하면 서명·HMAC으로 변조 여부를 확인하고 `ObjectInputFilter` 허용목록으로 클래스를 제한한다. 새 가젯이 계속 발견되므로 허용목록만으로는 충분하지 않다. 외부 입력으로 클래스·코드를 고르지 않는다. | [표준] CERT SER12-J, JEP 290 | LJ-02 |
| 캡슐화·객체 설계 | CWE-374·375·486·487·491·492·493·495·496·499·500·582·607·766·767 | 필드는 `private final`을 기본으로 하고, 가변 객체·배열은 방어적 복사로 주고받는다. `public static` 가변 필드를 두지 않는다. | [표준] CERT OBJ01-J·OBJ05-J | LJ-03 |
| 예외 처리 | CWE-209·248·395·396·397·460·537 | 빈 `catch`, `catch(Throwable)`, `NullPointerException` 포착(시험 장치 코드 제외), `finally` 안의 `return`을 금지한다. 예외 메시지에 민감정보를 넣지 않는다. | [표준] CERT ERR00-J·ERR04-J·ERR08-J | LJ-05(→I-06) |
| 자원·동시성 | CWE-362·366·543·567·572·585·609 | `try-with-resources`로 자원을 닫는다. 공개 객체를 락으로 쓰지 않고 락 획득 순서를 문서화한다. 공유 변수는 원자 클래스·불변 객체·락으로 보호한다. `volatile`은 가시성만 보장하므로 단순 플래그처럼 값을 대입만 하는 변수에 쓰고, 증가·검사 후 갱신 같은 복합 연산에는 원자 클래스나 락을 쓴다. | [표준] CERT ERR54-J·LCK00-J·VNA00-J·VNA02-J | LJ-06(→I-07) |
| 수치·비교 | CWE-191·192·197·595·597·1235·1335 | 크기·인덱스 계산은 `Math.addExact`·`multiplyExact`·`toIntExact`를 쓰고 축소 변환 전에 범위를 검사한다. 객체 내용 비교에는 `equals`를 쓴다. | [표준] CERT NUM00-J·NUM12-J | LJ-07(추가) |
| 객체 수명 관련 메서드 | CWE-568·580·581·583·586 | `finalize()`·`clone()`·`equals()`/`hashCode()` 규약을 코드 규약과 정적 분석 규칙으로 점검한다. | [CWE] 각 항목 완화책 | LJ-09(6.2) |
| 삽입·경로 | CWE-22·78·89(보안약점 점검 목록) | SQL은 `PreparedStatement`, 외부 프로세스는 `ProcessBuilder` 인자 배열을 쓰고, 경로는 정규화 후 허용 디렉터리 안인지 확인한다. | [표준] CERT IDS00-J·IDS07-J·FIO16-J | LJ-04(→I-04) |
| JNI 경계 | CWE-111 | JNI는 래퍼 클래스 한 곳으로 제한하고, 배열 길이와 null을 Java 쪽에서 먼저 검증한다. 네이티브 쪽에는 C/C++ 지침을 적용한다. | [표준] CERT JNI00-J | LJ-08 |
| XML 해석 | CWE-611(보조 항목) | 외부 XML은 `DocumentBuilderFactory`·`SAXParserFactory`에 `disallow-doctype-decl` 기능을 켜고 `XMLInputFactory`는 `SUPPORT_DTD`를 `false`로 둔 해석기로 읽는다. DTD가 필요하거나 `TransformerFactory`·`SchemaFactory`·`Validator`를 쓰면 `ACCESS_EXTERNAL_DTD`·`ACCESS_EXTERNAL_SCHEMA`·`ACCESS_EXTERNAL_STYLESHEET`를 빈 문자열로 두고, `XMLInputFactory`를 뺀 공장에서는 `FEATURE_SECURE_PROCESSING`도 코드에서 켠다. | [표준] Oracle Java SE 21 JAXP 보안 가이드[^jaxp-611], CERT IDS17-J, Find Security Bugs XXE 패턴 9개 | LJ-02(관련 I-03) |

**도구가 잡지 못하는 경우와 대안.** SEI CERT IDS17-J는 이 규칙의 자동 탐지 가능성을 'No'로 적는다. Find Security Bugs는 XXE 패턴 9개에 CWE-611을 붙이지만, 경고가 없다는 것만으로 안전으로 판정하지 않는다. XML 공장을 만드는 곳(`DocumentBuilderFactory`·`SAXParserFactory`·`XMLInputFactory`·`TransformerFactory`·`SchemaFactory`의 `newInstance` 계열)을 코드 리뷰 점검표에 넣어 위 설정을 확인한다(I-09).

JVM 전체 기본값은 사용자 정의 JAXP 설정 파일(`java.xml.config.file`)이나 시스템 속성으로 세 외부 접근 속성을 빈 값으로 두어 보완한다. 공장 API에서 둔 값이 시스템 속성·설정 파일보다 우선하므로 이 보완은 코드 설정을 대신하지 않는다. 외부 접근 속성을 `file`로만 제한하면 로컬 파일은 여전히 읽히므로 빈 값을 쓴다. 사용자 리졸버(`EntityResolver`·`XMLResolver`·`URIResolver`·`LSResourceResolver`)가 null이 아닌 입력을 돌려주면 외부 접근 속성이 적용되지 않으므로 리졸버는 허용목록으로 만든다.

> **사례 상자 5-3 — 언어별 구현 지침의 결함·구현 사례**
> 이 사례는 지침이 실제 임베디드 코드에 쓰인 예다. 무기체계 적합성을 입증하지 않는다.
>
> - [사례·확인] (LC-04 → I-02) PX4-Autopilot v1.17.0, CVE-2026-32743 — 1.17.0-rc2 이하의 `MavlinkLogHandler`가 너비 지정자 없는 `sscanf`로 60바이트 `LogEntry.filepath` 버퍼를 넘치게 한 스택 버퍼 오버플로(CWE-121). (확인 2026. 10. 15.)
> - [사례·확인] (LC-05 → I-05) CVE-2021-31571(FreeRTOS 10.4.3 이전 `queue.c` 큐 생성의 정수 오버플로), CVE-2026-5476(NASA cFS 7.0.0 이하, 32비트 `CFE_TBL_ValidateCodecLoadSize`의 정수 오버플로, CWE-190). (확인 2026. 10. 15.)
> - [사례·확인] (LCPP-05 → I-05) F´(F Prime) v4.4.1, `cmake/flags.cmake:51-58` — 검증 대상 경고 집합에 C++용 `-Wold-style-cast`와 `-Wconversion`, `-Werror`를 포함한다. (확인 2026. 10. 15.)
> - [사례·확인] (LJ-04, 관련 I-04) Yamcs yamcs-5.13.6, CVE-2026-55559 — 5.12.8·5.13.2 이전에 REST로 받은 `templateArgs`를 이스케이프 없이 YAML에 넣어 서비스 항목을 삽입할 수 있었음(CWE-94). (확인 2026. 10. 15.)

## 5.6 C# 지침(보조, CWE 뷰 없음)

C#은 CWE 언어 뷰가 없지만 매뉴얼 정적시험의 적용 언어다. 매뉴얼 부록 7은 적용 언어를 C, C++, Java, C#으로 정하되 자동화 도구가 지원하지 않는 경우는 제외한다([표준] 매뉴얼 부록 7, 인쇄 7-2쪽). 따라서 C#은 취약점 점검 대상이지만, 점검 기준이 될 언어 뷰가 없다. 이 공백은 보안약점 점검 목록 44개와 CWE-658/660의 언어 무관 항목을 골라 C# 점검 기준표를 만들고 협의 절차(2.5)로 확정하는 방식으로 메운다(LCS-01 → T-01 비해당 판정). 관리형 코드에서는 메모리 경계 항목 대부분이 생기지 않지만, `unsafe` 블록과 P/Invoke 경계에서는 C/C++와 같은 결함이 생길 수 있으므로 그 범위에는 5.3 지침을 적용한다.

대표 보안약점 칸은 '—'로 둔다(대응 CWE는 LCS-01 점검 기준표에서 정한다, 3.5). 언어와 관계없이 적용하는 보조 항목(부록 A-3) 행만 CWE를 적는다. 규칙 번호는 Microsoft .NET 코드 분석 규칙(CA)이다.

| 묶음(위험) | 대표 보안약점 | 구현 지침 | 규칙·도구 근거 | 지침 ID |
|---|---|---|---|---|
| `unsafe`·P/Invoke | — | `unsafe` 코드와 네이티브 호출은 전용 어셈블리 한 곳에 두고 나머지 프로젝트는 `AllowUnsafeBlocks`를 끈다(기본값 false). `DllImport` 문자열 마샬링과 DLL 탐색 경로를 명시하고, 핸들은 `SafeHandle`로 감싼다. | [표준] Microsoft Learn `AllowUnsafeBlocks`, CA2101, CA5392(조회 2026. 10. 15.) | LCS-02, LCS-04 |
| 직렬화 | — | `BinaryFormatter`·`SoapFormatter`·`NetDataContractSerializer`·`LosFormatter`를 쓰지 않는다. Newtonsoft.Json의 `TypeNameHandling`은 `None`으로 두고, `DataSet`·`DataTable`의 `ReadXml`은 신뢰한 입력에만 쓴다. | [표준] Microsoft Learn BinaryFormatter 보안 가이드, CA2300 계열, CA2326~CA2330, CA2350~CA2356·CA2361·CA2362 | LCS-03 |
| XML 해석 | CWE-611(보조 항목) | 외부 XML은 `XmlReaderSettings`의 `DtdProcessing`을 `Prohibit`으로 둔 `XmlReader`로 읽고 `XmlUrlResolver`를 쓰지 않는다. `XmlSerializer`·`DataSet`·`XPathDocument`·스키마도 그 `XmlReader`로 읽는다. | [표준] CA3061, CA5366, CA5369~CA5372, CA5374(CA3075·CA3077은 .NET Framework 대상에서만 동작) | LCS-03, LCS-09(관련 I-03) |
| 정수 | — | 크기·인덱스 계산은 `checked` 컨텍스트나 `CheckForOverflowUnderflow` 옵션으로 오버플로를 예외로 만든다(옵션 기본값은 미설정). | [표준] Microsoft Learn checked·unchecked 문서 | LCS-05(추가) |
| 자원 수명 | — | `IDisposable` 객체는 `using`으로 감싸고 종료자에 정리를 맡기지 않는다. | [표준] CA2000, CA1816 | LCS-06 |
| 암호·난수 | — / CWE-916(보조 항목) | 보안 용도 난수는 `RandomNumberGenerator`를 쓰고 `System.Random`을 금지한다. MD5·SHA-1·DES·3DES와 ECB 운용 모드를 쓰지 않는다. 비밀번호 저장·비밀번호 기반 키 유도에는 `PasswordDeriveBytes`를 쓰지 않고, `Rfc2898DeriveBytes`에 기본값(SHA-1)보다 강한 해시와 충분한 반복 횟수를 지정한다. | [표준] CA5350, CA5351, CA5358, CA5394, CA5373·CA5379·CA5387·CA5388 | LCS-07(→D-05) |
| 인증서·TLS | CWE-295·299(보조 항목) | 서버 인증서 검증 콜백(`ServerCertificateValidationCallback` 등)이 무조건 `true`를 돌려주게 하지 않는다. 인증서 폐기 목록 검사를 끄지 않고, 루트 인증서 저장소에 인증서를 추가하지 않는다. TLS 판(`SslProtocols`·`SecurityProtocolType`)은 코드에 고정하지 않고 폐기된 판을 지정하지 않는다. | [표준] CA5359, CA5380·CA5381, CA5399·CA5400, CA5364·CA5386·CA5397·CA5398 | LCS-07(→D-05) |
| 압축 해제 | — | 정비·업데이트 패키지를 풀 때 압축 항목 경로를 대상 경로에 그대로 쓰지 않는다. 경로를 정규화한 뒤 기준 디렉터리 안인지 확인한다. | [표준] CA5389 | LCS-09(관련 I-04) |
| 예외·null | — | 빈 `catch`와 불필요한 `catch(Exception)`을 금지하고, Nullable 참조 형식 경고를 오류로 올린다. | [표준] CA1031, Microsoft Learn Nullable reference types | LCS-08(→I-06) |

**분석기 설정.** Microsoft.CodeAnalysis.NetAnalyzers의 보안 규칙은 Security 범주 규칙이다. 규칙 번호의 앞자리(CA2xxx·CA3xxx·CA5xxx)로 범주를 가르지 않는다. CA2000(Reliability)·CA2101(Globalization)은 CA2xxx지만 Security 범주가 아니다. .NET 10 기본값에서는 Security 범주 규칙이 하나도 경고로 켜지지 않는다.

.NET SDK 10.0.402에 든 분석 모드 구성으로 세면 Default·Minimum 모드는 0개, Recommended 모드는 94개 중 24개, All 모드는 94개를 켠다(규칙 문서의 94개와는 한 건 다르다. 문서에는 CA2109가, SDK 구성에는 CA3005가 있다). 이 가이드가 예시 검증에 쓴 CA2100·CA2300·CA5390·CA5394는 Recommended에 없어 All 모드에서만 켜진다. 그래서 프로젝트 파일에 `<AnalysisMode>All</AnalysisMode>`(이 가이드의 예시 검증 설정)를 두거나, Security 범주만 올릴 때는 `<AnalysisModeSecurity>All</AnalysisModeSecurity>`를 두거나 `AnalysisLevelSecurity`를 버전-모드 값으로 고정한다.

범주별로 올리면 이 가이드가 기대는 Security 밖 규칙(CA1031·CA1065는 Design, CA2000은 Reliability, CA1816은 Usage, CA1819는 Performance, CA2101은 Globalization)은 그 범주를 따로 켠다. .NET Framework나 .NET Standard 대상 프로젝트는 `EnableNETAnalyzers`를 `true`로 두어야 분석기가 돈다.

Microsoft 문서는 보안 규칙을 끌 때 사유를 코드에 표시하고 과제의 보안 담당자에게 알리라고 한다. 이 가이드는 끈 규칙과 사유를 코딩규칙점검·취약점점검 FA 사유서(매뉴얼 제2024-6호 부록 7 별첨 1-7·1-8, 인쇄 7-22쪽)에 적는다(LCS-09, T-01). [근거] Microsoft Learn 코드 분석 개요·Security rules·MSBuild 속성 문서(dotnet/docs 커밋 고정본, 조회 2026. 10. 18.)

**도구가 잡지 못하는 경우와 대안.** 규칙이 있어도 대상 조건이 맞지 않으면 도구 미지원과 같다(6.2).

- CA3001~CA3012(SQL·경로·명령·XPath 삽입 등 오염 추적 규칙)는 HTTP 요청 입력만 추적한다. 규칙 문서는 신뢰할 수 없는 HTTP 요청 입력이 위험한 호출에 닿는 경우를 발생 조건으로 설명한다. 이 가이드의 실험(.NET SDK 10.0.402, `net10.0`, AnalysisMode All)에서 콘솔 입력을 쓰는 C# CWE-22·78 나쁜 예는 경고가 0건이었다. 데스크톱·서비스 소프트웨어의 콘솔·파일·소켓 입력에서 생기는 삽입은 정적 분석 경고 0건으로 판정하지 않고, 코드 리뷰(I-09)와 공격 입력을 넣은 실행 시험으로 확인한다. CA2100(SQL 명령문)은 입력 출처를 보지 않아 같은 실험에서 경고했다.
- CA3075·CA3077(안전하지 않은 DTD 처리)은 분석기 소스상 .NET Framework 대상에서만 동작한다. `net10.0` 대상 실험에서 `DtdProcessing.Parse`와 `XmlTextReader`를 쓴 코드도 CA3075·CA3077 경고가 0건이었다. 같은 코드를 `net48` 대상으로 빌드하면 CA3075가 경고했고, `XmlDocument`·`XmlTextReader`를 상속한 클래스에는 CA3077이 경고했다. 다만 .NET Framework 대상 SDK 형식 프로젝트에서 `AnalysisMode`만 `All`로 두면 어떤 분석 규칙도 경고하지 않았으므로, `AnalysisLevel`을 `latest-all` 같은 버전-모드 값으로 두거나 규칙 심각도를 `.editorconfig`에 직접 적는다(.NET SDK 10.0.402). .NET(Core 이후) 대상은 `DtdProcessing.Parse`·`XmlUrlResolver`를 BannedApiAnalyzers(`BannedSymbols.txt`)로 금지하거나 코드 리뷰 점검표에 넣는다(보조 항목 CWE-611).
- CA5385(RSA 키 길이)는 같은 실험에서 `RSA.Create(1024)`를 경고하지 않았다. 서명·암호 키 길이는 설계값(D-05)으로 정하고 코드 리뷰에서 확인한다.
- SecurityCodeScan은 마지막 릴리스가 5.6.7(2022. 9. 5.)이다. 쓰려면 사용하는 .NET SDK와의 호환을 먼저 확인한다.

**Microsoft .NET 보안 규칙 대응표.** Security 범주 규칙 94개를 CWE와 C# 지침에 대응시킨 표는 [부록 D-1](appendix/d-security-rules.md#d-1)에 있다. 규칙 문서에는 CWE 번호가 없어 대응은 이 가이드의 판단이고, BinaryFormatter 보안 가이드가 CWE-502를 연결하는 BinaryFormatter·LosFormatter·NetDataContractSerializer 관련 7개만 Microsoft 문서에 근거가 있다.

데스크톱·서비스 형태의 무기체계 C# 소프트웨어를 기준으로 해당 50개, 조건부 26개, 비해당 18개(웹 전용 14개, Azure Storage 3개, 폐기 규칙 1개)로 판정했다. 웹 UI(ASP.NET)를 두는 과제는 웹 전용 14개의 비해당 판정을 다시 해 LCS-01 점검 기준표에 적는다.

## 5.7 Python 지침(보조, CWE 언어 뷰 없음)

**매뉴얼과의 관계.** 매뉴얼에서 Python의 위치는 1.2를 따른다. 부록 7의 정적시험 적용 언어는 C, C++, Java, C#이고([표준] 매뉴얼 제2024-6호 부록 7, 인쇄 7-2쪽), 부록 6 코딩규칙의 적용 언어도 C, C++, C#, Java다([표준] 매뉴얼 부록 6, 인쇄 6-2쪽).

**Python의 보안약점.** 보안 점검을 권고하는 근거는 다음과 같다. KISA 「Python 시큐어코딩 가이드」는 구현단계 보안약점 제거 기준 49개 가운데 언어 특성상 해당하지 않는 3개(메모리 버퍼 오버플로우, 해제된 자원 사용, 초기화되지 않은 변수 사용)를 뺀 46개를 Python 기준으로 설명한다([표준] 인쇄 4·5쪽). MITRE CWE 5.0도 이 가이드 범위 197개 가운데 28개의 적용 언어에 Python을 적는다(예: CWE-22·78·89·95·502, [CWE] 각 항목의 적용 플랫폼). 점검 항목은 아래 Bandit 규칙과 6.7·7.4의 의존성 취약점 점검, 퍼징, 배포 전 검사다.

신뢰성시험 범위 포함 여부와 보안 점검 범위는 요구사항 분석 단계에서 정해 기록한다(3.5, LPY-01). 시험 합부 판정에 영향을 주는 스크립트는 결과의 신뢰성에 직결되므로 입력·출력 사양과 검증 결과를 문서화하고 형상관리(configuration management)한다. [보완]

Python에는 CWE 언어 뷰도 MISRA류 코딩규칙도 없으므로, Bandit 규칙과 린터 규칙을 조직 기준으로 정해 쓴다. CWE 5.0에는 OpenSSF 「Secure Coding Guide for Python」(2026)이 다루는 약점을 모은 뷰 CWE-1449(48개, 197개 안 24개)가 새로 생겼다. 이 뷰는 그 지침의 대응표이고 적용 언어로 정의한 언어 뷰가 아니므로, 범위는 197개를 유지하고 참고 자료로 쓴다. Bandit 규칙 75개 전체와 CWE의 대응은 [부록 D-2](appendix/d-security-rules.md#d-2)에 있다. 아래 표는 이 가이드가 구현 지침으로 삼는 규칙을 위험 묶음으로 모은 것이다('묶음(위험)' 칸은 그 규칙이 잡는 패턴, '규칙·도구 근거' 칸은 Bandit 규칙 번호). '대표 보안약점' 칸은 이 가이드의 대응이며, Bandit이 결과에 붙이는 CWE와 다른 행이 있다[^bandit-cwe]. [근거] Bandit 1.9.4·Python 3.13 문서(조회 2026. 10. 15.), Bandit 1.9.4 소스의 규칙별 CWE(대조 2026. 10. 18.), 언어 환경 지침 LPY-03~08(부록 C)

| 묶음(위험) | 대표 보안약점 | 구현 지침 | 규칙·도구 근거 | 지침 ID |
|---|---|---|---|---|
| `pickle`과 이를 감싼 모듈(`shelve.open` 등), `marshal`로 신뢰할 수 없는 데이터 역직렬화 | CWE-502 | 외부 데이터는 JSON이나 `yaml.safe_load`와 스키마 검증으로 읽는다. | Bandit B301·B302 | LPY-03 |
| 표준 라이브러리 XML 해석기(`xml.etree`·`minidom`·`sax` 등)로 신뢰할 수 없는 XML 해석 | CWE-611(보조 항목) | 외부 XML은 `defusedxml`로 해석한다. | Bandit B313~B319·B405~B409 | LPY-03(관련 I-03) |
| `eval` 사용 | CWE-95 | `eval`·`exec`·`compile`에 외부 입력을 넘기지 않고 전용 파서를 쓴다. `ast.literal_eval`도 깊게 중첩된 입력으로 메모리·스택을 소모시킬 수 있으므로 신뢰할 수 없는 데이터에는 쓰지 않는다. | Bandit B307 | LPY-04 |
| `shell=True` 서브프로세스, `os.system`·`os.popen` 등 셸 호출, 부분 경로로 실행 파일 지정 | CWE-78 | 셸을 거치지 않고 인자를 리스트로 넘기며 실행 파일은 절대 경로로 지정한다. | Bandit B602·B605·B607 | LPY-05(→I-04) |
| `/tmp`·`/var/tmp`·`/dev/shm` 같은 하드코드된 임시 경로, `mktemp`, 검사 없는 `tarfile` 해제 | CWE-22·59 | 임시 파일은 `tempfile.mkstemp`로 만들고, `tarfile` 해제 때는 `filter='data'`를 쓴다. | Bandit B108·B306·B202 | LPY-06(→I-04) |
| 표준 의사난수 생성기의 보안 용도 사용, 입력 검증에 쓴 `assert` | CWE-330·703 | 보안 용도는 `secrets` 모듈을 쓴다. `assert`는 `-O` 실행 때 제거되므로 입력 검증에 쓰지 않는다. | Bandit B311·B101 | LPY-07(→D-05·I-03) |
| `hashlib`의 MD5·SHA-1 같은 약한 해시의 보안 용도 사용 | CWE-327 | 무결성·인증 용도에 MD5·SHA-1을 쓰지 않는다. | Bandit B324(`hashlib`), B303(pycryptodome·cryptography의 MD5 등) | LPY-07(→D-05) |
| 하드코드된 비밀번호(문자열·함수 인자·기본값) | CWE-259 | 비밀을 소스에 두지 않는다. | Bandit B105·B106·B107 | LPY-07, LPY-12 |
| `requests`의 `verify=False`, 인증서를 검증하지 않는 `ssl` 문맥, SSH 호스트 키 검증 생략 | CWE-295(보조 항목) | 인증서·호스트 키 검증을 끄지 않는다. 폐기된 SSL/TLS 판도 지정하지 않는다(B502~B504). | Bandit B501·B323·B507 | LPY-07(→D-05) |
| `try-except-pass`, 반복문 안 `except`-`continue`로 예외를 조용히 무시 | CWE-390·755 | 예외는 구체 형식으로 처리하고, 실패를 시험 통과로 처리하지 않도록 종료 코드를 전파한다. | Bandit B110·B112 | LPY-08(→I-06) |

[^bandit-cwe]: Bandit 1.9.4는 임시 파일 규칙(B108·B306)에 CWE-377을 붙이지만, 이 번호는 CWE 5.0에서 폐기되어 매핑에 쓰지 않으므로 이 표에는 적지 않았고, 부록 D-2는 'Bandit의 CWE' 칸에 원래 표기로 남기되 대응은 CWE-59로 잡았다. Bandit 1.9.4 소스의 규칙 정의(플러그인·거부목록(blacklist))는 B307(`eval`)·B102(`exec`)에 CWE-78, B110·B112에 CWE-703, B506(`yaml.load`)과 XML 해석 규칙(B313~B319·B405~B409)에 CWE-20을 붙인다. 이 표는 약점의 결과를 기준으로 대응을 잡았다(`eval`은 CWE-95, 예외 무시는 CWE-390·755). XML 규칙은 Bandit이 경고하는 XML 공격을 외부 개체 참조(CWE-611)로 대응하고, 부록 D-2는 개체 확장(CWE-776)을 함께 적는다. 실제 발생 여부는 해석기 설정과 Python·expat 판에 따라 다르다. Bandit 결과를 CWE로 보고할 때는 이 차이를 점검 기준표에 적는다. B303은 pycryptodome·cryptography의 MD5 등만 보고 `hashlib.md5`는 B324가 본다.

## 5.8 특성에 따른 구현 보정

이 단계의 특성 보정은 활동마다 '강화·대체 지침'에 있다. 구현 수단을 크게 바꾸는 특성과 다루는 곳은 다음과 같다. 그 밖의 특성별 대체 수단은 8.1을 본다.

- **언어 런타임(L1)**: 네이티브-비안전(C·C++)이면 I-02·I-05를 적용하고, 관리형 언어와 인터프리터 언어는 5.5~5.7의 대응 지침을 쓴다(5.2).
- **컴파일러 보호 기능 지원(L2)**: 부분 지원이거나 없으면 I-08의 수단을 8.1의 대체 활동으로 바꾸고 "대체됨"으로 기록한다(I-08).
- **타깃 외(호스트) 빌드(L3)**: 가능하면 I-10 호스트 동적 분석을 적용한다.
- **자료형 모델(H5)**: 비표준이면 정수 지침을 강화한다(5.3).

## 5.9 단계 자가점검표

구현 단계 자가점검표(5-1~5-15)는 [부록 G-5 구현 단계](appendix/g-worksheets.md#g-5-impl)에 있다. 구현을 마치거나 코드 리뷰를 할 때 그 표로 스스로 확인한다.

---

[^jaxp-611]: Oracle 「Java API for XML Processing (JAXP) Security Guide」(Java SE 21, <https://docs.oracle.com/en/java/javase/21/security/java-api-xml-processing-jaxp-security-guide.html>), Java SE 21 API [`XMLConstants`](https://docs.oracle.com/en/java/javase/21/docs/api/java.xml/javax/xml/XMLConstants.html)·[`XMLInputFactory`](https://docs.oracle.com/en/java/javase/21/docs/api/java.xml/javax/xml/stream/XMLInputFactory.html)(조회 2026. 10. 28.). JDK XML 처리기는 기본으로 외부 자원을 가져오고, SAX·DOM·검증 공장은 FSP가 기본으로 켜져 있어도 외부 연결을 막지 않는다. 외부 접근 속성의 JDK 기본값은 `all`이고, StAX는 FSP를 지원하지 않는다. 이 가이드의 실험(JDK 21.0.12, 2026. 10. 28.)에서 기본 설정의 DOM·SAX·StAX·XSLT 변환·스키마 검증은 같은 폴더의 시험 파일을 가리키는 외부 개체를 모두 읽었고, 외부 접근 속성을 `file`로만 제한하면 로컬 파일 내용이 그대로 들어왔다. Find Security Bugs 1.14.0은 XXE 패턴 9개에 CWE-611을 붙인다([`findbugs.xml`](https://raw.githubusercontent.com/find-sec-bugs/find-sec-bugs/version-1.14.0/findsecbugs-plugin/src/main/resources/metadata/findbugs.xml)).
