rule Surrogate_Capability_Added
{
    strings:
        $sg = "Surrogate-Capability:" nocase
    condition:
        $sg
}