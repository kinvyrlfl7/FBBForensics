# FBBForensics

`Showcase_CLI_v1_clear.py`를 Visual Studio 2022에서 열 수 있는 Qt Widgets 기반 디지털 포렌식 워크벤치로 옮긴 버전입니다.

## 열기

Visual Studio 2022에서 아래 파일을 열면 됩니다.

- `FBBForensics.sln`

## 기본 Qt 경로

프로젝트는 기본적으로 아래 Qt 경로를 사용하도록 설정되어 있습니다.

- `C:\Qt\6.10.2\msvc2022_64`

## libtsk 필수 설정

이 프로젝트는 `libtsk`를 반드시 사용합니다. Visual Studio에서 `FBBForensics.props`의 아래 값을 환경에 맞게 채워야 합니다.

- `TskIncludeDir`: `tsk/libtsk.h`를 포함하는 상위 include 경로
- `TskLibraryDir`: Release용 `libtsk.lib` 경로
- `TskDebugLibraryDir`: Debug용 `libtsk.lib` 경로

기본값은 저장소 루트 아래 `third-party\sleuthkit`을 사용하도록 되어 있습니다. 단, Git 저장소에는 대용량/바이너리 의존성인 `third-party` 폴더를 포함하지 않습니다.

## 추가 의존성

저장소에는 소스 코드와 Visual Studio 프로젝트 파일만 포함합니다. 아래 항목은 각 개발 환경에서 별도로 준비해야 합니다.

- Qt 6.10.2 MSVC 2022 x64: 기본 경로 `C:\Qt\6.10.2\msvc2022_64`
- libtsk Debug/Release 빌드 산출물
- zlib Debug/Release 라이브러리 및 DLL
- bzip2 Debug/Release 라이브러리
- 테스트 이미지, 복구 결과, SQLite 분석 DB

## 결과 저장 구조

선택한 출력 폴더 아래 3개 파일로 분리 저장됩니다.

- `partition.db`
- `bootice.db`
- `fbinsttool.db`

## DB 역할

- `partition.db`: 저장장치 및 이미지 파일의 기본 파티션 정보와 분석 요약
- `bootice.db`: Bootice / EasyBoot / UltraISO 관련 정보
- `fbinsttool.db`: Fbinst 메타데이터, 파일 리스트, 섹터 추적 정보, 내부 시그니처 카빙 결과

## 내부 시그니처 기반 Fbinst 카빙

`Fbinst Remaining Sectors` 화면에서 `Carve Remaining Sectors`를 누르면 앱 내부 카버로 잔여 섹터를 카빙합니다.

- `Primary`: 각 512바이트 섹터의 앞 510바이트만 이어 붙인 논리 스트림에서 header/footer를 검색합니다.
- `Extended`: 각 512바이트 섹터 전체를 이어 붙인 raw 스트림에서 header/footer를 검색합니다.
- 주요 지원 포맷은 `7z`, `au`, `avi`, `bmp`, `bz2`, `docx`, `flv`, `gif`, `gz`, `jpg`, `mov`, `mp3`, `mp4`, `mpg`, `pcx`, `pdf`, `png`, `pptx`, `rar`, `tar`, `tif`, `wav`, `wim`, `wma`, `wmv`, `xlsx`, `zip`입니다.
- 결과는 출력 폴더의 `fbinsttool_carving` 아래에 저장되고, `fbinsttool.db`의 `Fbinst_Carved_Files` 테이블에 파일명, 확장자, 크기, SHA-256, 논리 오프셋, 카버 이름, 신뢰도가 기록됩니다.

## GitHub 업로드 정책

`.gitignore`는 다음 항목을 제외합니다.

- 빌드 산출물: `.vs`, `bin`, `obj`, `out`
- 분석 산출물: `partition.db`, `bootice.db`, `fbinsttool.db`, WAL/SHM 파일
- 테스트/증거 이미지: `*.001`, `*.dd`, `*.E01`, `FileCarving_TestImages`, `Hidden_TestImages`
- 복구 결과: `ExtractResult_*`, `fbinsttool_carving`
- 대용량 의존성/도구: `third-party`, `testdisk-7.2`, `testdisk-*.zip`

## 실행 정책

- 앱은 Visual Studio 2022에서 실행 시 관리자 권한을 요청하도록 설정되어 있습니다.
- 이미지 파일과 Physical Drive는 모두 읽기 전용으로만 열고 분석합니다.
- 출력은 선택한 폴더의 SQLite DB와 추출 파일에만 기록됩니다.

## 참고

- Bootice 내부 파일 파싱은 `libtsk`를 통해서만 수행됩니다.
- `libtsk`가 이미지를 열지 못하면 fallback 없이 분석 실패로 처리됩니다.
- 현재 프로젝트는 `third-party\\sleuthkit`의 `libtsk.lib` 빌드 설정과 맞추기 위해 Debug는 `/MTd`, Release는 `/MT` 런타임으로 빌드됩니다.
- 실행 시 Debug는 `qsqlited.dll`, Release는 `qsqlite.dll`을 복사하도록 설정되어 있습니다.





