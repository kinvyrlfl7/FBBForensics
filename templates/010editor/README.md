# 010 Editor Templates for FBBForensics

This folder contains Binary Templates for manually inspecting the hidden-area structures that FBBForensics parses.

- `FbinstTool.bt`: Detects the sector-0 `FBBF` marker, parses the sector-64 SubMBR, File_List sectors, and version-dependent File_List entries.
- `Bootice.bt`: Detects Bootice/EasyBoot markers, parses sector-96 hidden partition metadata, sector-99 signatures, the hidden FAT32 BPB, and the first root-directory cluster.

Use these templates on a raw disk image or a physical disk stream. If the evidence is compressed E01, open a decompressed/mounted raw view in 010 Editor first unless your 010 Editor setup exposes the logical disk stream directly.

