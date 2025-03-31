rule X_Tiny_Added
{
    strings:
        $tiny_header = "X-Tinyproxy:"

    condition:
        $tiny_header
}