rule PowerMad {
   meta:
      description = "Detect PowerMad, detection based on variables instead of description/common text in case attacker strips it"
      author = "Dan Lussier"
   strings:
      $x1 = "Machine account $account was not added"
      $x2 = "No remaining machine accounts to try"
      $x3 = "Total machine accounts added = $($j - 1)"

   condition:
      filesize < 2MB and all of them
}
