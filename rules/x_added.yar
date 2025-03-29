rule X_Header_Added
{
    strings:
        $x_header = "X-" nocase
    condition:
        $x_header
}