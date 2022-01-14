rule detect_mortar_edr_bypass {
   meta:
      description = "Mortar EDR Bypass, written in Pascal. This rule should detect Mortar being used on an encrypted file."
      author = "Dan Lussier"
      reference = "https://github.com/0xsp-SRD/mortar"
 
   strings:
      $s1 = "c:\\\\windows\\\\system32\\\\cmd.exe" fullword ascii
      $s2 = "BLOWFISH" fullword ascii
      $s3 = "TBlowFishDeCryptStream" fullword ascii
      $s4 = "TBlowFishStream" fullword ascii
      $s5 = "EBlowFishError" fullword ascii
      $s6 = "blowfish.serremptypassphrasenotallowed" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1024KB and
      all of them
}
