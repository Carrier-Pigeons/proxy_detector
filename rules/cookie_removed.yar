rule Cookie_Removed
{
    strings:
        $cookie = "Cookie:" nocase
    condition:
        not $cookie
}