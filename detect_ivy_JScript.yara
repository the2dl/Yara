rule detect_ivy_JScript {
    meta:
        author = "Dan Lussier"
	description = "Detect Ivy JScript files"
	reference_url = "https://github.com/optiv/Ivy"

    strings:
        $re1 = /new\sActiveXObject\(\"(Word|Excel|PowerPoint)\.Application\"\);/
        $re2 = /Visible\s\=\sfalse;/
        $re3 = /new\sActiveXObject\(\"WScr\"\+\"ipt\.Shell\"\);/

    condition:
        all of them and filesize < 7340032
}
