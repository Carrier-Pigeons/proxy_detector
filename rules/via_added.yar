rule Via_Added
{
    strings:
        $via = "Via:" nocase
    condition:
        $via
}