# FBBForensics

FBBForensics is a Qt Widgets-based forensic analysis tool for examining FbinstTool and Bootice structures in disk images and physical drives.

It records partition metadata, Bootice-related artifacts, FbinstTool metadata, Fbinst file lists, sector coverage, and internally carved files into separate SQLite databases.

## Opening The Project

Open the following solution file in Visual Studio 2022:

- `FBBForensics.sln`

## Default Qt Path

The project is configured to use the following Qt installation by default:

- `C:\Qt\6.10.2\msvc2022_64`

If your Qt installation is in a different location, update `QtInstallDir` in `FBBForensics.props`.

## Required libtsk Configuration

This project requires The Sleuth Kit (`libtsk`). Update the following properties in `FBBForensics.props` to match your local environment:

- `TskIncludeDir`: the include root that contains `tsk/libtsk.h`
- `TskLibraryDir`: the Release directory containing `libtsk.lib`
- `TskDebugLibraryDir`: the Debug directory containing `libtsk.lib`

The default values expect `third-party\sleuthkit` under the repository root. The `third-party` directory is intentionally excluded from Git because it contains large binary dependencies.

## Additional Dependencies

Only source code and Visual Studio project files are stored in this repository. Prepare the following dependencies locally:

- Qt 6.10.2 MSVC 2022 x64
- The Sleuth Kit (`libtsk`) Debug and Release builds
- zlib Debug and Release libraries and DLLs
- bzip2 Debug and Release libraries
- Test images, recovered files, and SQLite analysis databases

## Output Database Layout

Analysis results are written to three SQLite database files in the selected output directory:

- `partition.db`
- `bootice.db`
- `fbinsttool.db`

## Database Roles

- `partition.db`: basic partition information, storage/image metadata, and analysis summary records
- `bootice.db`: Bootice, EasyBoot, and UltraISO-related records
- `fbinsttool.db`: FbinstTool metadata, file list records, sector coverage, remaining sector information, and internal carving results

## Internal FbinstTool Carving

Use `Carve Remaining Sectors` from the `Fbinst Remaining Sectors` view to carve data from unallocated or remaining FbinstTool sectors.

- `Primary`: builds a logical stream from the first 510 bytes of each 512-byte sector.
- `Extended`: builds a raw stream from all 512 bytes of each sector.
- The internal carver validates supported formats using format-aware strategies such as header/footer, header/length, structure parsing, and validation-based checks.
- Supported formats include `7z`, `au`, `avi`, `bmp`, `bz2`, `docx`, `flv`, `gif`, `gz`, `jpg`, `mov`, `mp3`, `mp4`, `mpg`, `pcx`, `pdf`, `png`, `pptx`, `rar`, `tar`, `tif`, `wav`, `wim`, `wma`, `wmv`, `xlsx`, and `zip`.
- Recovered files are stored under `fbinsttool_carving`, and metadata is recorded in the `Fbinst_Carved_Files` table.

## Read-Only Evidence Handling

- Disk images and physical drives are opened read-only.
- The application requests administrator privileges when launched from Visual Studio 2022.
- Output is written only to the selected output directory and consists of SQLite databases and extracted/recovered files.

## GitHub Storage Policy

The `.gitignore` file excludes files that should not be committed:

- Build output: `.vs`, `bin`, `obj`, `out`
- Analysis output: `partition.db`, `bootice.db`, `fbinsttool.db`, WAL/SHM files
- Evidence and test images: `*.001`, `*.dd`, `*.E01`, `FileCarving_TestImages`, `Hidden_TestImages`
- Recovered files: `ExtractResult_*`, `fbinsttool_carving`
- Large binary dependencies and tools: `third-party`, `testdisk-7.2`, `testdisk-*.zip`

## Notes

- Bootice internal file parsing is performed through `libtsk`.
- If `libtsk` cannot open an image, the analysis fails without falling back to a non-libtsk parser.
- Debug builds use `/MTd`, and Release builds use `/MT` to match the current local `libtsk.lib` build configuration.
- Debug builds copy `qsqlited.dll`; Release builds copy `qsqlite.dll`.
