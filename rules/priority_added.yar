rule Priority_Added
{
    strings:
        $priority = "priority:" nocase
    condition:
        $priority
}