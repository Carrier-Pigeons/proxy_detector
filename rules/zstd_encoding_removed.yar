rule ZSTD_Encoding_Removed
{
    strings:
        $zstd_header = /(\n)Accept-Encoding:.+zstd/
    condition:
        not $zstd_header
}