# Recycle Bin Parser
This tool is made to parse $I and $R artifacts from the C:\\\$Recycle.Bin folder in
Windows Vista/7/8/8.1/10.

## Usage
```
Usage: parse_recyclebin_artifacts.py [options] arg

Options:
  -h, --help            show this help message and exit
  -o OUTPUT, --output=OUTPUT
  -f FORMAT, --format=FORMAT
  -v, --verbose
```

Example:
```bash
python parse_recyclebin_artifacts.py -f csv -o results.csv "C:\$Recycle.Bin\SID_HERE\$IAFB43F.txt"
```

## Technical Details
When a file is deleted on Windows versions after Vista, its usually just being moved
to a folder labeled with your users SID within C:\\\$Recycle.Bin folder
(unless the file is too large for the bin). The file is renamed to \$R followed by 6
random alphanumeric characters plus the original file extension. A new file is created
along side this \$R file which starts with \$I and has the *same* 6 random characters
followed by the original file extension of the "deleted" file. This \$I file holds
metadata about the original file (\$R). This tool is capable of reading these \$I
files and printing the results to the screen or exporting the data to a CSV or JSON
file.

### $I Recycle Bin File Format (Windows Vista/8/8/8.1)
Offset | Num Bytes | Info
- | - | -
0 | 8 | Windows Version Code (01)
8 | 8 | Deleted file's size
16 | 8 | Deletion timestamp in Windows 64 bit FILEFORMAT
24 | 520 | Deleted file's original path

### $I Recycle Bin File Format (Windows 10)
Offset | Num Bytes | Info
- | - | -
0 | 8 | Windows Version Code (02)
8 | 8 | Deleted file's size
16 | 8 | Deletion timestamp in Windows 64 bit FILEFORMAT
24 | 4 | Length of deleted file's original path in bytes
28 | n | Deleted file's original path
