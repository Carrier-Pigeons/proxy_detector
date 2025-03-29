rule No_False
{
    strings:
        $this_wont_exist = "9238475623948572364958237456"
    condition:
        $this_wont_exist
}