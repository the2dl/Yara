rule ScareCrow_CobaltStrike_DLL {
   meta:
      description = "Detect ScareCrow DLL Payloads (and other Go Shellcode Loaders)"
      author = "Dan Lussier"
   strings:
      $x1 = " Go buildinf:"
      $x2 = "fatal error: cgo callback before cgo call"
      $x3 = "victim"
      $x4 = "hashMightPanic"
      $x5 = "*[8]dnsmessage.Type"
      $x6 = "*func() *reflect.rtype"
      $x7 = "!*func() *reflectlite.uncommonType"
      $x8 = "?*struct { lock runtime.mutex; used uint32; fn func(bool) bool }"
   condition:
      uint16(0) == 0x5a4d and filesize < 8000KB and
      6 of ($x*)
}
