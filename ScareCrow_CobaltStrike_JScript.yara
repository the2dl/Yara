rule ScareCrow_CobaltStrike_JScript {
    meta:
        author = "Dan Lussier"
	description = "Detect ScareCrow JScript files, this includes DLL and CPL methods"

    strings:
        $re1 = /ExpandEnvironmentStrings\(\"\%TEMP\%\"\).{1,50}.dll/
        $re2 = /ExpandEnvironmentStrings\(\"\%TEMP\%\"\).{1,50}.cpl/

    condition:
        1 of ($re*) and filesize < 7340032
}
