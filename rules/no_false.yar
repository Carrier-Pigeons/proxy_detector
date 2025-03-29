rule No_False
{
    strings:
        $no_false = ":"
    condition:
        not $no_false
}