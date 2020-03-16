$env:Path = "c:\Program Files\Veritas\NetBackup\bin\admincmd";
$SrcDP = "<DISK Pool Name source>";
$TgtDP = "<DISK Pool Name target>";
$TgtSTU = "<Target Storage Uniut>";
$StoreType = "<tape storage, example: DataDomain, etc>";
$BIDfile = "<File name to generate Backup ID to move>";
$DupLog = "<path to log, example - C:\Program Files\Veritas\NetBackup\logs\user_ops\bpdup.ls>";

bpimmedia.exe -l -stype $StoreType -dp $SrcDP | Select-String "IMAGE" | %{([string]$_).Split()[2]} > $BIDfile

bpduplicate -dstunit $TgtSTU -Bidfile $BIDfile -L $DupLog -dp $TgtDP -cn 1 -rl 8 -set_primary 1
