rule havoc_c2_payload_detection
{
   meta:
      description = "Havoc C2 Framework Detection"
      author = "the2dl"
      reference = "https://github.com/HavocFramework/Havoc"
      state = "emerging"
   strings:
      $h1 = { 61 6D 73 69 2E 64 6C 6C 41 54 56 53 48 }
   condition:
      uint16(0) == 0x5a4d and all of them
}
