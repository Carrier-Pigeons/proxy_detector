rule DNT_Header_Capitalization
{
    strings:
        $dnt_old = "DNT" nocase
        $dnt_new = "Dnt"
    condition:
        not $dnt_old or ($dnt_old and $dnt_new)
}