rule default_CobaltStrike_SMB_Lateral_Movement_EXE {
    meta:
        author = "Dan Lussier"
	description = "Detect default cobaltstrike lateral movement payloads"

    strings:
        $s1 = "%c%c%c%c%c%c%c%c%cpipe-%d"
        $s2 = "Mingw-w64 runtime failure:"
        $s3 = "CreateNamedPipeA"
        $s4 = "CreateProcessA"
        $s5 = "CreateThread"
        $s6 = "CreateFileA"
        $s7 = "VirtualAllocEx"

    condition:
        all of them and filesize < 900KB
}
