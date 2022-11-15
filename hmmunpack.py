"""Script to extract files from HMMSys Packed objects.

The format is partially documented here:

    http://wiki.xentax.com/index.php/Rising_Kingdoms_PAK

    Format Specifications
    char {16}    - Header ("HMMSYS PackFile" + (byte)10)
    uint32 {4}   - Unknown (26)
    byte {12}    - null
    uint32 {4}   - Number Of Files
    uint32 {4}   - Directory Length [+40 archive header]

    // for each file

    byte {1}     - Filename Length
    byte {1}     - Previous Filename Reuse Length
    char {X}     - Filename Part (length = filenameLength - previousFilenameReuseLength)
    uint32 {4}   - File Offset
    uint32 {4}   - File Length

    // Presumably after the directory...

    byte {X}     - Padding (repeating 153,121,150,50) until first file offset
    byte {X}     - File Data

There is a simple Ruby script that can do the same as this here:

    * https://github.com/meh/fffs/blob/862887a2214e146f70b7eb362a6120fe3225fb1a/examples/pak.rb

A russian forum also discusses the format:

    * https://forum.df2.ru/index.php?showtopic=8683

Notes from developing the script below:

In reality I don't think we have an accurate directory length value, but
we can find the directory at 40 bytes. After we have the directory, we
can read as many bytes as needed up until the end of the file to create
directory entries for as many "number of files" there are. The File
records themselves are accurate, and we find ourselves able tp process
them one by one pretty easily.

The format is more easily rendered as:

    +=============================================+
    |               HMM Packfile                  |
    +=============================================+
    | Format header (40 bytes)                    |
    +---------------------------------------------+
    | File directory (n-bytes * no_files)         |
    | (1, 1, max(255), max(255), 4, 4) * no_files |
    +---------------------------------------------+
    | Padding (no_files * 4-bytes)                |
    +---------------------------------------------+
    | Files (n-bytes * no_files * file_length)    |
    +---------------------------------------------+

"""

import argparse
import os
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Final, List

sig: Final[str] = "HMMSYS PackFile"
header_length: Final[int] = 40
samples: Final[Path] = Path("samples")
byte_order: Final[str] = "little"
max_dir_len: Final[int] = 522  # 1, 1, max(255), max(255), 4, 4


class ArgError(Exception):
    """Provide feedback to the caller if there is a problem with the
    arguments supplied to the script.
    """


class ProcessError(Exception):
    """To raise when there are issues processing the pack file."""


def pretty_hex(data: bytes) -> str:
    """Pretty-print hexadecimal."""
    print(type(data))
    return " ".join("{:02x}".format(char) for char in data)


def process_header(header: bytes) -> int:
    """Process the HMM Packfile header and perform integrity checks.

    Returns the number of files in the packfile, and directory length
    to be processed further by the script.

    Example data:

        sig: 48 4d 4d 53 59 53 20 50 61 63 6b 46 69 6c 65 0a
        unknown constant: 1a 00 00 00 == 0x1a000000
        null: 00 00 00 00 00 00 00 00 00 00 00 00
        files: 43 00 00 00
        dirlen: ec 11 00 00

    """
    sig = header[:16]
    unk = header[16:20]
    _ = header[
        20:32
    ]  # Null-bytes are unused, but we could employ this for further integrity checks.
    files = header[32:36]
    _ = header[
        36:40
    ]  # Supposed to be dir_len but the values are too big, and don't seem to align with any format boundaries.
    hmm_sig: Final[str] = "HMMSYS PackFile\x0a"
    hmm_check: Final[str] = b"\x1a\x00\x00\x00"
    assert (
        sig.decode("utf8") == hmm_sig
    ), f"HMMSYS signature not '{hmm_sig}' but: '{sig}'"
    assert (
        unk == hmm_check
    ), f"HMMSYS check-bytes not '{pretty_hex(hmm_check)}' but: '{pretty_hex(unk)}'"
    no_files = int.from_bytes(files, byteorder=byte_order)
    return no_files


@dataclass
class File:
    """File object for storing metadata about the binary objects that
    we're processing.
    """

    offset: int = 0
    length: int = 0
    filename: str = ""
    fname_len: int = 0
    reuse_len: int = 0
    actual_name: str = ""

    def __repr__(self) -> str:
        """Return a prettier representation of the object to output
        streams.
        """
        return f"({self.filename}: {self.offset}, {self.length} ({self.reuse_len}))"


def process_directory(directory: bytes, no_files: int) -> List[File]:
    """The directory is reliably processed using the following offsets:

        byte {1}     - Filename Length
        byte {1}     - Previous Filename Reuse Length
        char {X}     - Filename Part (length = filenameLength - previousFilenameReuseLength)
        uint32 {4}   - File Offset
        uint32 {4}   - File Length

    At the end of the directory, and before the beginning of the packed
    files themselves is a padded space, no_files * 4 bytes long. We do
    not process this information yet, but it is extracted and stored.

    File metadata is stored in a dataclass and the structures returned
    in a list to the caller.
    """
    processed = 0
    files = []

    dir_length = 0

    while processed < no_files:
        fi = File()
        fname_len = int.from_bytes(directory[:1], byteorder=byte_order)
        reuse_len = int.from_bytes(directory[1:2], byteorder=byte_order)
        fname_part = fname_len - reuse_len
        fname = directory[2 : 2 + fname_part]
        file_offset = 2 + fname_part
        file_length = file_offset + 4
        file_off = int.from_bytes(
            directory[file_offset : file_offset + 4], byteorder=byte_order
        )
        file_len = int.from_bytes(
            directory[file_length : file_length + 4], byteorder=byte_order
        )

        fi.offset = file_off
        fi.length = file_len
        fi.filename = fname.decode("utf8")
        fi.fname_len = fname_len
        fi.reuse_len = reuse_len

        files.append(fi)
        eof = file_length + 4

        dir_length += eof

        directory = directory[eof:]
        processed += 1

    additional_data_len = no_files * 4
    _ = directory[
        :additional_data_len
    ]  # Likely padding data, but potentially useful as it aligns with the no. of files.

    first_file_offset = (
        dir_length + additional_data_len + header_length
    )  # Calculation for the first file offset
    assert (
        files[0].offset == first_file_offset
    ), f"First file offsets don't match: {files[0].offset} {first_file_offset}"

    print(f"Directory length: {dir_length}", file=sys.stderr)
    print(f"Padding length: {additional_data_len}", file=sys.stderr)

    return files


def find_and_create_dirs(output_dir: Path, path: str) -> None:
    """Given a path, identify the directories and then create them
    accordingly.
    """
    path = path.replace("\\", "/")
    path = os.path.split(path)[0]
    pak_paths = Path(output_dir / path)
    pak_paths.mkdir(parents=True, exist_ok=True)


def process_files(files: List[File], data: bytes, packname: str) -> None:
    """Process (extract) the files from the packfile.

    Files are read from the file list, and a directory structure created
    as necessary. The files are then processed from the marked offset to
    the offset + file_len and saved into the directory structure.
    """
    output_dir = Path(f"output-{packname}")
    try:
        # A little defensively, if the folder exists we want to know,
        # then we can delete it, and then create it new. It should only
        # ever contain the contents of the pakfile, and no additional
        # detritus.
        output_dir.mkdir(parents=True, exist_ok=False)
    except FileExistsError:
        shutil.rmtree(output_dir)
        output_dir.mkdir(parents=True, exist_ok=False)
    last = ""
    all_files_len = 0
    for item in files:
        all_files_len += item.length
        fname = item.filename
        # File names are lightly compressed. If a reuse length 'n' is
        # set, then the given filename includes the first 'n' bytes of
        # the previous file name. Filenames also include path separators
        # denoting the structure of the packfile.
        if item.reuse_len > 0:
            fname = f"{last[:item.reuse_len]}{fname}"
        find_and_create_dirs(output_dir, fname)
        item.actual_name = fname
        last = fname
        try:
            with open(str(output_dir / Path(fname)), "wb") as extracted_file:
                extracted_file.write(data[item.offset : item.offset + item.length])
        except (FileNotFoundError, PermissionError) as err:
            print(f"Error extracting: {fname}: {err}", file=sys.stderr)
            pass
    extracted = [f"- {item.actual_name}\n" for item in files]
    archive_name = packname.replace("\\", "-").replace("/", "-")
    extract_report = f"extract-report-{archive_name}.txt"
    with open(extract_report, "w", encoding="utf8") as report:
        report.write("Extracted files:\n")
        report.write("".join(extracted))
    print(f"No. bytes extracted: {all_files_len}", file=sys.stderr)
    print(f"Extract details at: {Path(extract_report).absolute()}", file=sys.stderr)


def extract(path: Path) -> None:
    """Extract files from a HMM packfile."""
    packfile_name = str(path)

    data = None
    with open(str(path), "r+b") as extract_file:
        data = extract_file.read()

    print(f"File size: {len(data)}", file=sys.stderr)

    data_len = len(data)
    header = data[:header_length]
    no_files = process_header(header)

    approx_dir_len = no_files * max_dir_len + (no_files * 4)
    if approx_dir_len > data_len:
        # We could just send all the data to process as a directory,
        # but we want to get to a position where we accurately know
        # the length.
        raise ProcessError("Cannot calculate directory length without causing overflow")

    dir_from = header_length
    directory = data[dir_from : dir_from + approx_dir_len]
    files = process_directory(directory, no_files)

    print(f"No. files: {no_files}", file=sys.stderr)

    process_files(files, data, packfile_name)


def validate_path_arg(path: str) -> Path:
    """Validates the path argument supplied to the script."""
    if not Path(path).exists():
        raise ArgError(f"Supplied path does not exist: {path}")
    return Path(path)


def args() -> str:
    """Process the script's arguments."""
    parser = argparse.ArgumentParser(
        prog="HMM Packfile Extractor",
        description="Extracts objects from the legacy HMM packfile format",
        epilog="Let me know if you find it useful at all, https://github.com/ross-spencer/hmmunpack",
    )
    parser.add_argument(
        "file",
        metavar="FILE",
        type=str,
        nargs=1,
        help="a path to a hmm packfile to unpack",
    )
    args = parser.parse_args()
    return validate_path_arg(args.file[0])


def main() -> None:
    """Primary entry point for this script."""
    try:
        path = args()
    except ArgError as err:
        return sys.exit(f"{err}")
    extract(path)


if __name__ == "__main__":
    main()
