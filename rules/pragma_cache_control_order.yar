rule Pragma_Cache_Control_Order
{
    strings:
        $pragma = "Pragma: no-cache" nocase
        $cache_control = "Cache-Control: no-cache" nocase
    condition:
        $pragma at 4 and $cache_control at 5
}