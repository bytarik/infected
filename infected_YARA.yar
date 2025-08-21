rule infected_YARA
{
    meta:
        description = "infected için zararlı yazılım tespit kuralı"
        author = "5_GRUP"
        date = "2025-08-21"
        threat_level = "High"

    strings:
        // ASCII string'ler (küçük-büyük harfe duyarlı)
        $str1 = "XU9HDA724PL4LQHY6BE4EKX9ZNGR47A0"
        $str2 = "9PU2UBNL91730ZQ5KEC"
        $str3 = "6KTBYBC8IM84W0043AT9AXFACBE2LAKZ"
        $str4 = "1ECP5MDR2U2X2A3AYIF8MSP3A7I1UBMY"
        $str5 = "RH2Y7KH7"
        $str6 = "X0I5VCFB8NR71URTM4ENIR0FVPTGXOVJR7OMDYHSYBJPOSB3ZVZE17DG9DKGS"
        $str7 = "computernewb.comj/elijah/bw/bundle.js"
        $str8 = "computernewb.com"
        $str9 = "SELECT HOST_KEY, is_httponly, path, is_secure, (expires_utc/1000000)-11644480800, name, encrypted_value from cookies"
		$str10 = "SELECT host, isHttpOnly, path, isSecure, expiry, name, value FROM moz_cookies"
		$str11 = "FRBN8RR0PJXZMO3JURFOC5ZS7I"
		$str12 = "6AV7Y0281LPFN4EGEYVYRHXHEOG"
        // Hash (örneğin MD5) - ASCII olarak
        $hash1 = "093bd44ab3d5ddbf928ae2b0a662d394"

        // Hexadecimal string'ler (örnek olarak string'lerin hex karşılıkları)
        $hex_str1 = { 58 55 39 48 44 41 37 32 34 50 4C 34 4C 51 48 59 36 42 45 34 45 4B 58 39 5A 4E 47 52 34 37 41 30 } // XU9HDA724PL4LQHY6BE4EKX9ZNGR47A0
        $hex_str2 = { 39 50 55 32 55 42 4E 4C 39 31 37 33 30 5A 51 35 4B 45 43 } // 9PU2UBNL91730ZQ5KEC
        $hex_str3 = { 36 4B 54 42 59 42 43 38 49 4D 38 34 57 30 30 34 33 41 54 39 41 58 46 41 43 42 45 32 4C 41 4B 5A } // 6KTBYBC8IM84W0043AT9AXFACBE2LAKZ
        $hex_str4 = { 31 45 43 50 35 4D 44 52 32 55 32 58 32 41 33 41 59 49 46 38 4D 53 50 33 41 37 49 31 55 42 4D 59 } // 1ECP5MDR2U2X2A3AYIF8MSP3A7I1UBMY
        $hex_str5 = { 52 48 32 59 37 4B 48 37 } // RH2Y7KH7
        $hex_str6 = { 58 30 49 35 56 43 46 42 38 4E 52 37 31 55 52 54 4D 34 45 4E 49 52 30 46 56 50 54 47 58 4F 56 4A 52 37 4F 4D 44 59 48 53 59 42 4A 50 4F 53 42 33 5A 56 5A 45 31 37 44 47 39 44 4B 47 53 } // X0I5VCFB8NR71URTM4ENIR0FVPTGXOVJR7OMDYHSYBJPOSB3ZVZE17DG9DKGS
        $hex_str7 = { 63 6F 6D 70 75 74 65 72 6E 65 77 62 2E 63 6F 6D 6A 2F 65 6C 69 6A 61 68 2F 62 77 2F 62 75 6E 64 6C 65 2E 6A 73 } // computernewb.comj/elijah/bw/bundle.js
        $hex_str8 = { 63 6F 6D 70 75 74 65 72 6E 65 77 62 2E 63 6F 6D } // computernewb.com
        $hex_hash1 = { 30 39 33 62 64 34 34 61 62 33 64 35 64 64 62 66 39 32 38 61 65 32 62 30 61 36 36 32 64 33 39 34 } // 093bd44ab3d5ddbf928ae2b0a662d394
		$hex_str11 = { 4652424E38525230504A585A4D4F334A5552464F43355A533749 }
		$hex_str12 = { 3641563759303238314C50464E3445474559565952485848454F47 }
    condition:
        // Koşul: String'lerden veya hex değerlerden en az biri bulunursa kural tetiklenir
        any of ($str*) or any of ($hex*) or $hash1
}