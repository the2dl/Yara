rule Havoc_Framework_Payload_Detection
{
   meta:
      description = "Havoc C2 Framework Detection"
      author = "the2dl"
      reference = "https://github.com/HavocFramework/Havoc"
      state = "emerging"
   strings:
      $h1 = { 3F 00 5C 00 43 00 3A 00 5C 00 57 00 69 00 6E 00 64 00 6F 00 77 00 73 00 5C 00 53 00 79 00 73 00 74 00 65 00 6D 00 33 00 32 00 5C 00 6E 00 74 00 64 00 6C 00 6C 00 2E 00 64 00 6C 00 6C 00 00 00 } // C:\Windows\System32\ntdll.dll
      $h2 = { 5B 5E 5F 5D 41 5C 41 5D 41 5E 41 5F } // [^_]A\A]A^A_ (regex matching)
   condition:
      uint16(0) == 0x5a4d and all of them
}
