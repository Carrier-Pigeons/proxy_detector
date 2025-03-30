rule Priority_Added
{
    strings:
        $x_header = "Priority:" nocase
    condition:
        $x_header
}