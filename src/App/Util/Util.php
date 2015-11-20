<?php

namespace App\Util;

class Util {

    public static function get_file_extension($file_name) {
        return substr(strrchr($file_name, '.'), 1);
    }

    /**
     * Extract numbers from a string
     * @param type $str
     * @return type
     */
    public static function get_numerics($str) {
        preg_match("/\d+/", $str, $matches);
        //preg_match_all('!\d+!', $str, $matches);
        return $matches[0];
    }

    /**
     * 
     * @param type $dec
     * @return type
     */
    public static function unichr($dec) {
        if ($dec < 128) {
            $utf = chr($dec);
        } else if ($dec < 2048) {
            $utf = chr(192 + (($dec - ($dec % 64)) / 64));
            $utf .= chr(128 + ($dec % 64));
        } else {
            $utf = chr(224 + (($dec - ($dec % 4096)) / 4096));
            $utf .= chr(128 + ((($dec % 4096) - ($dec % 64)) / 64));
            $utf .= chr(128 + ($dec % 64));
        }
        return $utf;
    }

    /*
     * Convert to safe characters
     * 
     * @desc : remove the accent not '-'
     */

    public static function vt_safe_vietnamese_meta($str, $lower = true, $vietnamese = true, $special = false, $accent = false) {
        $str = $lower ? strtolower($str) : $str;
        // Remove Vietnamese accent or not
        $str = $accent ? self::vt_remove_vietnamese_accent($str) : $str;

        // Replace special symbols with spaces or not
        $str = $special ? self::vt_remove_special_characters($str) : $str;

        // Replace Vietnamese characters or not
        $str = $vietnamese ? self::vt_replace_vietnamese_characters($str) : $str;

        return $str;
    }

    /*
     * Remove 5 Vietnamese accent / tone marks if has Combining Unicode characters
     * Tone marks: Grave (`), Acute(�), Tilde (~), Hook Above (?), Dot Bellow(.)
     */

    public static function vt_remove_vietnamese_accent($str) {

        $str = preg_replace("/[\x{0300}\x{0301}\x{0303}\x{0309}\x{0323}]/u", "", $str);

        return $str;
    }

    /*
     * Remove or Replace special symbols with spaces
     */

    public static function vt_remove_special_characters($str, $remove = true) {

        // Remove or replace with spaces
        $substitute = $remove ? "" : " ";

        $str = preg_replace("/[\x{0021}-\x{002D}\x{002F}\x{003A}-\x{0040}\x{005B}-\x{0060}\x{007B}-\x{007E}\x{00A1}-\x{00BF}]/u", $substitute, $str);

        return $str;
    }

    /*
     * Replace Vietnamese vowels with diacritic and Letter D with Stroke with corresponding English characters
     */

    public static function vt_replace_vietnamese_characters($str) {

        $str = preg_replace("/[\x{00C0}-\x{00C3}\x{00E0}-\x{00E3}\x{0102}\x{0103}\x{1EA0}-\x{1EB7}]/u", "a", $str);
        $str = preg_replace("/[\x{00C8}-\x{00CA}\x{00E8}-\x{00EA}\x{1EB8}-\x{1EC7}]/u", "e", $str);
        $str = preg_replace("/[\x{00CC}\x{00CD}\x{00EC}\x{00ED}\x{0128}\x{0129}\x{1EC8}-\x{1ECB}]/u", "i", $str);
        $str = preg_replace("/[\x{00D2}-\x{00D5}\x{00F2}-\x{00F5}\x{01A0}\x{01A1}\x{1ECC}-\x{1EE3}]/u", "o", $str);
        $str = preg_replace("/[\x{00D9}-\x{00DA}\x{00F9}-\x{00FA}\x{0168}\x{0169}\x{01AF}\x{01B0}\x{1EE4}-\x{1EF1}]/u", "u", $str);
        $str = preg_replace("/[\x{00DD}\x{00FD}\x{1EF2}-\x{1EF9}]/u", "y", $str);
        $str = preg_replace("/[\x{0110}\x{0111}]/u", "d", $str);

        return $str;
    }

    public static function alias($str) {
        $str = preg_replace("/(à|á|ạ|ả|ã|â|ầ|ấ|ậ|ẩ|ẫ|ă|ằ|ắ|ặ|ẳ|ẵ|À|Á|Ạ|Ả|Ã|Â|A|Ầ|Ấ|Ậ|Ẩ|Ẫ|Ă|Ằ|Ắ|Ặ|Ẳ|Ẵ)/", "a", $str);
        $str = preg_replace("/(B)/", "b", $str);
        $str = preg_replace("/(C)/", "c", $str);
        $str = preg_replace("/(đ|D|Đ)/", "d", $str);
        $str = preg_replace("/(è|é|ẹ|ẻ|ẽ|ê|ề|ế|ệ|ể|ễ|È|É|Ẹ|E|Ẻ|Ẽ|Ê|Ề|Ế|Ệ|Ể|Ễ)/", "e", $str);
        $str = preg_replace("/(F)/", "f", $str);
        $str = preg_replace("/(G)/", "g", $str);
        $str = preg_replace("/(H)/", "h", $str);
        $str = preg_replace("/(ì|í|ị|ỉ|ĩ|Ì|Í|Ị|Ỉ|Ĩ)/", "i", $str);
        $str = preg_replace("/(J)/", "j", $str);
        $str = preg_replace("/(K)/", "k", $str);
        $str = preg_replace("/(L)/", "l", $str);
        $str = preg_replace("/(M)/", "m", $str);
        $str = preg_replace("/(N)/", "n", $str);
        $str = preg_replace("/(ò|ó|ọ|ỏ|õ|ô|ồ|ố|ộ|ổ|ỗ|ơ|ờ|ớ|ợ|ở|ỡ|Ò|Ó|Ọ|Ỏ|Õ|Ô|Ồ|Ố|Ộ|Ổ|Ỗ|O|Ơ|Ờ|Ớ|Ợ|Ở|Ỡ)/", "o", $str);
        $str = preg_replace("/(P)/", "p", $str);
        $str = preg_replace("/(Q)/", "q", $str);
        $str = preg_replace("/(R)/", "r", $str);
        $str = preg_replace("/(S)/", "s", $str);
        $str = preg_replace("/(T)/", "t", $str);
        $str = preg_replace("/(ù|ú|ụ|ủ|ũ|ư|ừ|ứ|ự|ử|ữ|Ù|Ú|Ụ|Ủ|Ũ|Ư|Ừ|Ứ|Ự|Ử|Ữ)/", "u", $str);
        $str = preg_replace("/(V)/", "v", $str);
        $str = preg_replace("/(W)/", "w", $str);
        $str = preg_replace("/(X)/", "x", $str);
        $str = preg_replace("/(ỳ|ý|ỵ|ỷ|ỹ|Ỳ|Ý|Ỵ|Ỷ|Ỹ)/", "y", $str);
        $str = preg_replace("/(Z)/", "z", $str);
        $str = preg_replace("/(!|@|%|\^|\*|\(|\)|\+|\=|<|>|\?|\/|,|\.|\:|\;|\'|\"|\“|\”|\&|\#|\[|\]|~|$|_)/", "", $str);
        $str = str_replace("&*#39;", "", $str);
        $str = str_replace(" ", "-", $str);
        return $str;
    }

    public static function UUID($length = 8) {
        $chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        $password = substr(str_shuffle($chars), 0, $length);
        return $password;
    }

    /**
     * Strips the last extension off of a file name
     *
     * @param   string  $file  The file name
     *
     * @return  string  The file name without the extension
     *
     * @since   1.0
     */
    public static function stripExt($file) {
        return preg_replace('#\.[^.]*$#', '', $file);
    }

    /**
     * Makes the file name safe to use
     *
     * @param   string  $file        The name of the file [not full path]
     * @param   array   $stripChars  Array of regex (by default will remove any leading periods)
     *
     * @return  string  The sanitised string
     *
     * @since   1.0
     */
    public static function makeSafe($file, array $stripChars = array('#^\.#')) {
        $regex = array_merge(array('#(\.){2,}#', '#[^A-Za-z0-9\.\_\- ]#'), $stripChars);

        $file = preg_replace($regex, '', $file);

        // Remove any trailing dots, as those aren't ever valid file names.
        $file = rtrim($file, '.');

        return $file;
    }

    /**
     * Splits an URL into its parts
     *
     * @param string $url  The URL
     * @return array       An array containig the parts of the URL
     *
     *                     The keys are:
     *
     *                     "protocol" (z.B. "http://")
     *                     "host"     (z.B. "www.bla.de")
     *                     "path"     (z.B. "/test/palimm/")
     *                     "file"     (z.B. "index.htm")
     *                     "domain"   (z.B. "foo.com")
     *                     "port"     (z.B. 80)
     *                     "auth_username"
     *                     "auth_password"
     */
    public static function splitURL($url) {
        // Protokoll der URL hinzuf�gen (da ansonsten parse_url nicht klarkommt)
        if (!preg_match("#^[a-z]+://# i", $url))
            $url = "http://" . $url;

        $parts = @parse_url($url);

        if (!isset($parts)):
            return null;
        endif;

        $protocol = $parts["scheme"] . "://";
        $host = (isset($parts["host"]) ? $parts["host"] : "");
        $path = (isset($parts["path"]) ? $parts["path"] : "");
        $query = (isset($parts["query"]) ? "?" . $parts["query"] : "");
        $auth_username = (isset($parts["user"]) ? $parts["user"] : "");
        $auth_password = (isset($parts["pass"]) ? $parts["pass"] : "");
        $port = (isset($parts["port"]) ? $parts["port"] : "");

        // File
        preg_match("#^(.*/)([^/]*)$#", $path, $match); // Alles ab dem letzten "/"
        if (isset($match[0])) {
            $file = trim($match[2]);
            $path = trim($match[1]);
        } else {
            $file = "";
        }

        // Der Domainname aus dem Host
        // Host: www.foo.com -> Domain: foo.com
        $parts = @explode(".", $host);
        if (count($parts) <= 2) {
            $domain = $host;
        } else if (preg_match("#^[0-9]+$#", str_replace(".", "", $host))) { // IP
            $domain = $host;
        } else {
            $pos = strpos($host, ".");
            $domain = substr($host, $pos + 1);
        }

        // DEFAULT VALUES f�r protocol, path, port etc. (wenn noch nicht gesetzt)
        // Wenn Protokoll leer -> Protokoll ist "http://"
        if ($protocol == ""):
            $protocol = "http://";
        endif;

        // Wenn Port leer -> Port setzen auf 80 or 443
        // (abh�ngig vom Protokoll)
        if ($port == "") {
            if (strtolower($protocol) == "http://")
                $port = 80;
            if (strtolower($protocol) == "https://")
                $port = 443;
        }

        // Wenn Pfad leet -> Pfad ist "/"
        if ($path == ""):
            $path = "/";
        endif;

        // Rockgabe-Array
        $url_parts["protocol"] = $protocol;
        $url_parts["host"] = $host;
        $url_parts["path"] = $path;
        $url_parts["file"] = $file;
        $url_parts["query"] = $query;
        $url_parts["domain"] = $domain;
        $url_parts["port"] = $port;

        $url_parts["auth_username"] = $auth_username;
        $url_parts["auth_password"] = $auth_password;

        return $url_parts;
    }

    /**
     * Builds an URL from it's single parts.
     *
     * @param array $url_parts Array conatining the URL-parts.
     *                         The keys should be:
     *
     *                         "protocol" (z.B. "http://") OPTIONAL
     *                         "host"     (z.B. "www.bla.de")
     *                         "path"     (z.B. "/test/palimm/") OPTIONAL
     *                         "file"     (z.B. "index.htm") OPTIONAL
     *                         "port"     (z.B. 80) OPTIONAL
     *                         "auth_username" OPTIONAL
     *                         "auth_password" OPTIONAL
     * @param bool $normalize   If TRUE, the URL will be returned normalized.
     *                          (I.e. http://www.foo.com/path/ insetad of http://www.foo.com:80/path/)
     * @return string The URL
     *                         
     */
    public static function buildURLFromParts($url_parts, $normalize = false) {
        // Host has to be set aat least
        if (!isset($url_parts["host"])) {
            throw new Exception("Cannot generate URL, host not specified!");
        }

        if (!isset($url_parts["protocol"]) || $url_parts["protocol"] == "")
            $url_parts["protocol"] = "http://";
        if (!isset($url_parts["port"]))
            $url_parts["port"] = 80;
        if (!isset($url_parts["path"]))
            $url_parts["path"] = "";
        if (!isset($url_parts["file"]))
            $url_parts["file"] = "";
        if (!isset($url_parts["query"]))
            $url_parts["query"] = "";
        if (!isset($url_parts["auth_username"]))
            $url_parts["auth_username"] = "";
        if (!isset($url_parts["auth_password"]))
            $url_parts["auth_password"] = "";

        // Autentication-part
        $auth_part = "";
        if ($url_parts["auth_username"] != "" && $url_parts["auth_password"] != "") {
            $auth_part = $url_parts["auth_username"] . ":" . $url_parts["auth_password"] . "@";
        }

        // Port-part
        $port_part = ":" . $url_parts["port"];

        // Normalize
        if ($normalize == true) {
            if ($url_parts["protocol"] == "http://" && $url_parts["port"] == 80 ||
                    $url_parts["protocol"] == "https://" && $url_parts["port"] == 443) {
                $port_part = "";
            }

            // Don't add port to links other than "http://" or "https://"
            if ($url_parts["protocol"] != "http://" && $url_parts["protocol"] != "https://") {
                $port_part = "";
            }
        }

        // If path is just a "/" -> remove it ("www.site.com/" -> "www.site.com")
        if ($url_parts["path"] == "/" && $url_parts["file"] == "" && $url_parts["query"] == "")
            $url_parts["path"] = "";

        // Put together the url
        $url = $url_parts["protocol"] . $auth_part . $url_parts["host"] . $port_part . $url_parts["path"] . $url_parts["file"] . $url_parts["query"];

        return $url;
    }

    /**
     * Normalizes an URL
     *
     * I.e. converts http://www.foo.com:80/path/ to http://www.foo.com/path/
     *
     * @param string $url
     * @return string OR NULL on failure
     */
    public static function normalizeURL($url) {
        $url_parts = self::splitURL($url);

        if ($url_parts == null)
            return null;

        $url_normalized = self::buildURLFromParts($url_parts, true);
        return $url_normalized;
    }

    /**
     * Gets the HTTP-statuscode from a given response-header.
     *
     * @param string $header  The response-header
     * @return int            The status-code or NULL if no status-code was found.
     */
    public static function getHTTPStatusCode($header) {
        $first_line = strtok($header, "\n");

        preg_match("# [0-9]{3}#", $first_line, $match);

        if (isset($match[0]))
            return (int) trim($match[0]);
        else
            return null;
    }

    /**
     * Reconstructs a full qualified and normalized URL from a given link relating to the URL the link was found in.
     *
     * @param string $link          The link (i.e. "../page.htm")
     * @param PHPCrawlerUrlPartsDescriptor $BaseUrlParts  The parts of the URL the link was found in (i.e. "http://www.foo.com/folder/index.html")
     *
     * @return string The rebuild, full qualified and normilazed URL the link is leading to (i.e. "http://www.foo.com/page.htm")
     *                Or NULL if the link couldn't be rebuild correctly.
     */
    public static function buildURLFromLink($link, PHPCrawlerUrlPartsDescriptor $BaseUrlParts) {

        $url_parts = $BaseUrlParts->toArray();

        // Entities-replacements
        $entities = array("'&(quot|#34);'i",
            "'&(amp|#38);'i",
            "'&(lt|#60);'i",
            "'&(gt|#62);'i",
            "'&(nbsp|#160);'i",
            "'&(iexcl|#161);'i",
            "'&(cent|#162);'i",
            "'&(pound|#163);'i",
            "'&(copy|#169);'i");

        $replace = array("\"",
            "&",
            "<",
            ">",
            " ",
            chr(161),
            chr(162),
            chr(163),
            chr(169));

        // Remove "#..." at end, but ONLY at the end,
        // not if # is at the beginning !
        $link = preg_replace("/^(.{1,})#.{0,}$/", "\\1", $link);

        // Cases
        // Strange link like "//foo.htm" -> make it to "http://foo.html"
        if (substr($link, 0, 2) == "//") {
            $link = "http:" . $link;
        }

        // 1. relative link starts with "/" --> doc_root
        // "/index.html" -> "http://www.foo.com/index.html"    
        elseif (substr($link, 0, 1) == "/") {
            $link = $url_parts["protocol"] . $url_parts["host"] . ":" . $url_parts["port"] . $link;
        }

        // 2. "./foo.htm" -> "foo.htm"
        elseif (substr($link, 0, 2) == "./") {
            $link = $url_parts["protocol"] . $url_parts["host"] . ":" . $url_parts["port"] . $url_parts["path"] . substr($link, 2);
        }

        // 3. Link is an absolute Link with a given protocol and host (f.e. "http://...")
        // DO NOTHING
        elseif (preg_match("#^[a-z0-9]{1,}(:\/\/)# i", $link)) {
            $link = $link;
        }

        // 4. Link is stuff like "javascript: ..." or something
        elseif (preg_match("/^[a-zA-Z]{0,}:[^\/]{0,1}/", $link)) {
            $link = "";
        }

        // 5. "../../foo.html" -> remove the last path from our actual path
        // and remove "../" from link at the same time until there are
        // no more "../" at the beginning of the link
        elseif (substr($link, 0, 3) == "../") {
            $new_path = $url_parts["path"];

            while (substr($link, 0, 3) == "../") {
                $new_path = preg_replace('/\/[^\/]{0,}\/$/', "/", $new_path);
                $link = substr($link, 3);
            }

            $link = $url_parts["protocol"] . $url_parts["host"] . ":" . $url_parts["port"] . $new_path . $link;
        }

        // 6. link starts with #
        // -> leads to the same site as we are on, trash
        elseif (substr($link, 0, 1) == "#") {
            $link = "";
        }

        // 7. link starts with "?"
        elseif (substr($link, 0, 1) == "?") {
            $link = $url_parts["protocol"] . $url_parts["host"] . ":" . $url_parts["port"] . $url_parts["path"] . $url_parts["file"] . $link;
        }

        // 7. thats it, else the abs_path is simply PATH.LINK ...
        else {
            $link = $url_parts["protocol"] . $url_parts["host"] . ":" . $url_parts["port"] . $url_parts["path"] . $link;
        }

        if ($link == "")
            return null;


        // Now, at least, replace all HTMLENTITIES with normal text !!
        // Fe: HTML-Code of the link is: <a href="index.php?x=1&amp;y=2">
        // -> Link has to be "index.php?x=1&y=2"
        $link = preg_replace($entities, $replace, $link);

        // Replace linebreaks in the link with "" (happens if a links in the sourcecode
        // linebreaks)
        $link = str_replace(array("\n", "\r"), "", $link);

        // "Normalize" URL
        $link = self::normalizeUrl($link);

        return $link;
    }

    /**
     * Returns the redirect-URL from the given HTML-header
     *
     * @return string The redirect-URL or NULL if not found.
     */
    public static function getRedirectURLFromHeader(&$header) {
        // Get redirect-link from header
        preg_match("/((?i)location:|content-location:)(.{0,})[\n]/", $header, $match);

        if (isset($match[2])) {
            $redirect = trim($match[2]);
            return $redirect;
        } else
            return null;
    }

    /**
     * Gets the value of an header-directive from the given HTTP-header.
     *
     * Example:
     * <code>PHPCrawlerUtils::getHeaderValue($header, "content-type");</code>
     *
     * @param string $header    The HTTP-header
     * @param string $directive The header-directive
     *
     * @return string The value of the given directive found in the header.
     *                Or NULL if not found.
     */
    public static function getHeaderValue($header, $directive) {
        preg_match("#[\r\n]" . $directive . ":(.*)[\r\n\;]# Ui", $header, $match);

        if (isset($match[1]) && trim($match[1]) != "") {
            return trim($match[1]);
        } else
            return null;
    }

    /**
     * Returns all cookies from the give response-header.
     *
     * @param string $header      The response-header
     * @param string $source_url  URL the cookie was send from.
     * @return array Numeric array containing all cookies as PHPCrawlerCookieDescriptor-objects.
     */
    public static function getCookiesFromHeader($header, $source_url) {
        $cookies = array();

        $hits = preg_match_all("#[\r\n]set-cookie:(.*)[\r\n]# Ui", $header, $matches);

        if ($hits && $hits != 0) {
            for ($x = 0; $x < count($matches[1]); $x++) {
                $cookies[] = PHPCrawlerCookieDescriptor::getFromHeaderLine($matches[1][$x], $source_url);
            }
        }

        return $cookies;
    }

    /**
     * Returns the normalized root-URL of the given URL
     *
     * @param string $url The URL, e.g. "www.foo.con/something/index.html"
     * @return string The root-URL, e.g. "http://www.foo.com"
     */
    public static function getRootUrl($url) {
        $url_parts = self::splitURL($url);
        $root_url = $url_parts["protocol"] . $url_parts["host"] . ":" . $url_parts["port"];

        return self::normalizeURL($root_url);
    }

    /**
     * Serializes data (objects, arrays etc.) and writes it to the given file.
     */
    public static function serializeToFile($target_file, $data) {
        $serialized_data = serialize($data);
        file_put_contents($target_file, $serialized_data);
    }

    /**
     * Returns deserialized data that is stored in a file.
     *
     * @param string $file The file containing the serialized data
     *
     * @return mixed The data or NULL if the file doesn't exist
     */
    public static function deserializeFromFile($file) {
        if (file_exists($file)) {
            $serialized_data = file_get_contents($file);
            return unserialize($serialized_data);
        } else
            return null;
    }

    /**
     * Sorts a twodimensiolnal array.
     */
    public static function sort2dArray(&$array, $sort_args) {
        $args = func_get_args();

        // F�r jedes zu sortierende Feld ein eigenes Array bilden
        @reset($array);
        while (list($field) = @each($array)) {
            for ($x = 1; $x < count($args); $x++) {
                // Ist das Argument ein String, sprich ein Sortier-Feld?
                if (is_string($args[$x])) {
                    $value = $array[$field][$args[$x]];

                    ${$args[$x]}[] = $value;
                }
            }
        }

        // Argumente for array_multisort bilden
        for ($x = 1; $x < count($args); $x++) {
            if (is_string($args[$x])) {
                // Argument ist ein TMP-Array
                $params[] = &${$args[$x]};
            } else {
                // Argument ist ein Sort-Flag so wie z.B. "SORT_ASC"
                $params[] = &$args[$x];
            }
        }

        // Der letzte Parameter ist immer das zu sortierende Array (Referenz!)
        $params[] = &$array;

        // Array sortieren
        call_user_func_array("array_multisort", $params);

        @reset($array);
    }

    /**
     * Determinates the systems temporary-directory.
     *
     * @return string
     */
    public static function getSystemTempDir() {
        $dir = sys_get_temp_dir() . "/";
        return $dir;
    }

    /**
     * Checks wether the given string is an UTF8-encoded string.
     *
     * Taken from http://www.php.net/manual/de/function.mb-detect-encoding.php
     * (comment from "prgss at bk dot ru")
     * 
     * @param string $string The string
     * @return bool TRUE if the string is UTF-8 encoded.
     */
    public static function isUTF8String($string) {
        $sample = @iconv('utf-8', 'utf-8', $string);

        if (md5($sample) == md5($string))
            return true;
        else
            return false;
    }

    /**
     * Checks whether the given string is a valid, urlencoded URL (by RFC)
     * 
     * @param string $string The string
     * @return bool TRUE if the string is a valid url-string.
     */
    public static function isValidUrlString($string) {
        if (preg_match("#^[a-z0-9/.&=?%-_.!~*'()]+$# i", $string))
            return true;
        else
            return false;
    }

    /**
     * Decodes GZIP-encoded HTTP-data
     */
    public static function decodeGZipContent($content) {
        return gzinflate(substr($content, 10, -8));
    }

    /**
     * Checks whether the given data is gzip-encoded
     */
    public static function isGzipEncoded($content) {
        if (substr($content, 0, 3) == "\x1f\x8b\x08") {
            return true;
        } else {
            return false;
        }
    }

    /**
     * @desc turns line breaks in forms into HTML <br> <br/> or <p></p> tags
     * @param type $string
     * @param type $line_breaks
     * @param type $xml
     * @return type
     */
    public static function nl2p($string, $line_breaks = true, $xml = true) {
        // remove existing HTML formatting to avoid double tags
        $string = str_replace(array('<p>', '</p>', '<br>', '<br/>'), '', $string);

        // convert single line breaks into <br> or <br/> tags
        if ($line_breaks == true) {
            return '<p>' . preg_replace(array("/\r/", "/\n{2,}/", "/\n/"), array('', '</p><p>', '<br' . ($xml == true ? '/' : '') . '>'), $string) . '</p>';
        } else {
            return '<p>' . preg_replace("/\n/", "</p>\n<p>", trim($string)) . '</p>';
        }
    }

    public static function wordLimit($str, $limit = 100, $strip_tags = true, $end_char = ' &#8230;') {
        if (trim($str) == '') {
            return $str;
        }

        if ($strip_tags) {
            $str = trim(preg_replace('#<[^>]+>#', ' ', $str));
        }
        $words = explode(' ', $str);
        $words = array_filter($words);
        $string = '';
        if (count($words) > $limit) {
            $i = 0;
            foreach ($words as $word) {
                if ($i < $limit) {
                    $string.=$word . ' ';
                    $i++;
                } else {
                    break;
                }
            }
        } else {
            $string = $str;
        }

        $string = self::removeSpace($string);

        return rtrim($string) . $end_char;
    }

    public static function characterLimit($str, $limit = 150, $strip_tags = true, $end_char = ' &#8230;', $enc = 'utf-8') {
        if (trim($str) == '') {
            return $str;
        }

        if ($strip_tags) {
            $str = strip_tags($str);
        }

        if (strlen($str) > $limit) {
            if (function_exists("mb_substr")) {
                $str = mb_substr($str, 0, $limit, $enc);
            } else {
                $str = substr($str, 0, $limit);
            }
            return rtrim($str) . $end_char;
        } else {
            return $str;
        }
    }

    public static function random($length = 8, $possible = "0123456789abcdefghijklmnopqrstvwxyzABCDEFGHIJKLMNOPQRSXTUVYW") {
        // start with a blank string
        $string = "";

        // set up a counter
        $i = 0;

        // add random characters to $string until $length is reached
        while ($i < $length) {

            // pick a random character from the possible ones
            $char = substr($possible, mt_rand(0, strlen($possible) - 1), 1);

            // we don't want this character if it's already in the string
            if (!strstr($string, $char)) {
                $string .= $char;
                $i++;
            }
        }

        // done!
        return $string;
    }

    public static function Timer($timestamp) {
        $etime = time() - $timestamp;
        if ($etime < 1) {
            return 'bây giờ';
        }
        $a = array(365 * 24 * 60 * 60 => 'year',
            30 * 24 * 60 * 60 => 'month',
            7 * 24 * 60 * 60 => 'week',
            24 * 60 * 60 => 'day',
            60 * 60 => 'hour',
            60 => 'minute',
            1 => 'second'
        );
        $a_plural = array('year' => 'năm',
            'month' => 'tháng',
            'week' => 'tuần',
            'day' => 'ngày',
            'hour' => 'giờ',
            'minute' => 'phút',
            'second' => 'giây'
        );

        foreach ($a as $secs => $str) {
            $d = $etime / $secs;
            if ($d >= 1) {
                $r = round($d);
                return $r . ' ' . $a_plural[$str] . ' ' . 'trước';
            }
        }
    }

    public static function resizeIMG($path, $thumb_path, $width, $height, $type = "crop") {
        $src = new imageLib($path);
        $src->resizeImage($width, $height, $type, true);
        $src->saveImage($thumb_path);
        return true;
    }

    public function getDateInWeek($week, $year) {
        $time = strtotime("1 January $year", time());
        $day = date('w', $time);
        $time += ((7 * $week) + 1 - $day) * 24 * 3600;
        $return[0] = date('d-m-Y', $time);
        $time += 6 * 24 * 3600;
        $return[1] = date('d-m-Y', $time);
        return $return;
    }

}
