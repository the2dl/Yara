rule default_CobaltStrike_named_pipe {
    meta:
        author = "Dan Lussier"
	description = "If an attacker does not modify the artifactkit in CS, this exact string will always appear (MSSE)"

     strings:
        $s1 = "%c%c%c%c%c%c%c%c%cMSSE-%d-server"
        $s2 = "CreateNamedPipeA"

    condition:
        all of them and filesize < 400000

}
