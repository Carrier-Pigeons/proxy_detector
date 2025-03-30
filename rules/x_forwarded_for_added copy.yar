rule Via_Header_Added
{
    strings:
        $via_header = "via:" nocase
    condition:
        $via_header
}