rule default_CS_exe_detection {
    meta:
        author = "Dan Lussier"
	description = "Detect default CS EXE based payloads"

    strings:
        $s1 = "%c%c%c%c%c%c%c%c%cpipe-%d"
        $s2 = "Mingw-w64 runtime failure:"
        $s3 = "CreateNamedPipeA"
        $s4 = "HeapAlloc"

    condition:
        all of them and filesize < 400000
}
