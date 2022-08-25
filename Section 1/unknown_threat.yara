rule darklord {
        meta:
                Author = "@yelsayad"
                Description = "This rule detects darklord script"
        strings:
		$path="/tmp/SSH-One"
                $m="SSH-T"
		$script="SSH-One"
                $hfs_m="http://darkl0rd.com:7758/SSH-T"
                $hfs_s="http://darkl0rd.com:7758/SSH-One"
        condition:
                $path and $m and $script and $hfs_m and $hfs_s

}