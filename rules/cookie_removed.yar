rule Cookie_Removed
{
    strings:
        $cookie = "Cookie:"
    condition:
        not $cookie
}