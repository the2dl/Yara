rule Adobe_AppXBundle_Detection {
    meta:
        author = "Dan Lussier"
	description = "Identify malicious Adobe themed AppXBundles"

     strings:
        $e1 = "AppxSignature.p7x"
        $re1 = /Adobe\_.{1,20}.appxPK/
        $re2 = /Images\/.{1,20}/

    condition:
        all of them

}
