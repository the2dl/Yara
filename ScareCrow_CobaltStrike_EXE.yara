rule ScareCrow_CobaltStrike_EXE {
   meta:
      description = "ScareCrow EXE Detection (and other Go based shellcode loaders)"
      author = "Dan Lussier"
      reference = "https://github.com/optiv/ScareCrow/"
      date = "10-20-21"
   strings:
      $x1 = "00010203040506070809101112131415161718192021222324252627282930313233343536373839404142434445464748495051525354555657585960616263" ascii
      $x2 = "object is remotepacer: H_m_prev=reflect mismatchremote I/O errorruntime:  g:  g=runtime: addr = runtime: base = runtime: gp: gp=" ascii
      $x3 = " to unallocated span37252902984619140625Arabic Standard TimeAzores Standard TimeCertOpenSystemStoreWChangeServiceConfigWCheckTok" ascii
      $x4 = " > (den<<shift)/2unreserving unaligned region45474735088646411895751953125Central America Standard TimeCentral Pacific Standard " ascii
      $x5 = "152587890625762939453125Bidi_ControlCoCreateGuidCreateEventWCreateMutexWErrUnknownPCGetAddrInfoWGetConsoleCPGetLastErrorGetLengt" ascii
      $x6 = "0123456789abcdefghijklmnopqrstuvwxyz444089209850062616169452667236328125Go pointer stored into non-Go memoryUnable to determine " ascii
      $x7 = "entersyscallgcBitsArenasgcpacertracehost is downillegal seekinvalid slotiphlpapi.dllkernel32.dlllfstack.pushmadvdontneedmheapSpe" ascii
      $x8 = "slice bounds out of range [:%x] with length %ystopTheWorld: not stopped (status != _Pgcstop)sysGrow bounds not aligned to palloc" ascii
      $x9 = "lock: lock countslice bounds out of rangesocket type not supportedstartm: p has runnable gsstoplockedm: not runnableunexpected f" ascii
      $x10 = "unknown pcuser32.dllws2_32.dll  of size   (targetpc= KiB work,  freeindex= gcwaiting= heap_live= idleprocs= in status  mallocing" ascii
      $x11 = ".lib section in a.out corrupted11368683772161602973937988281255684341886080801486968994140625Central Brazilian Standard TimeCert" ascii
      $x12 = "EnumKeyExWRegEnumValueWRegOpenKeyExWRtlGetVersionShellExecuteWStartServiceWThread32FirstVirtualUnlockWTSFreeMemoryWriteConsoleWb" ascii
      $x13 = "structure needs cleaningzlib: invalid dictionary bytes failed with errno= to unused region of span with too many arguments 29103" ascii
      $x14 = "garbage collection scangcDrain phase incorrectindex out of range [%x]interrupted system callinvalid m->lockedInt = left over mar" ascii
      $x15 = ",M3.2.0,M11.1.0476837158203125<invalid Value>ASCII_Hex_DigitAddDllDirectoryCLSIDFromStringCreateHardLinkWDeviceIoControlDuplicat" ascii
      $x16 = "GOMAXPROCSGetIfEntryGetVersionGlagoliticIsValidSidKharoshthiLockFileExManichaeanOld_ItalicOld_PermicOld_TurkicOpenEventWOpenMute" ascii
      $x17 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Time Zonesbufio.Scanner: SplitFunc returns negative advance countcasfrom_Gscans" ascii
      $x18 = "1907348632812595367431640625CertCloseStoreControlServiceCreateEventExWCreateMutexExWCreateProcessWCreateServiceWCryptGenRandomCu" ascii
      $x19 = " P runtime: p scheddetailsechost.dllsecur32.dllshell32.dllshort writetracealloc(unreachableuserenv.dll KiB total,  [recovered] a" ascii
      $x20 = "1907348632812595367431640625CertCloseStoreControlServiceCreateEventExWCreateMutexExWCreateProcessWCreateServiceWCryptGenRandomCu" ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 9000KB and
      10 of ($x*)
}

