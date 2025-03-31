rule Dnt_Removed
{
    strings:
        $dnt = "DNT:" nocase
    condition:
        not $dnt
}