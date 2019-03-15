
static char *circl_server = NULL;
static char *circl_authinfo = NULL;

/* circl_url -- create a URL corresponding to a command-path string.
 *
 * the batch file and command line syntax are in native DNSDB API format.
 * this function has the opportunity to crack this into pieces, and re-form
 * those pieces into the URL format needed by some other DNSDB-like system
 * which might have the same JSON output format but a different REST syntax.
 *
 * CIRCL pDNS only "understands IP addresses, hostnames or domain names
 * (please note that CIDR block queries are not supported)". exit with an
 * error message if asked to do something the CIRCL server does not handle.
 * 
 * 1. RRSet query: rrset/name/NAME[/TYPE[/BAILIWICK]]
 * 2. Rdata (name) query: rdata/name/NAME[/TYPE]
 * 3. Rdata (IP address) query: rdata/ip/ADDR[/PFXLEN]
 */
static char *
circl_url(const char *path, char *sep) {
	const char *val = NULL;
	char *ret;
	int x;

	if (circl_server == NULL)
		circl_server = strdup(sys->server);
	if (strncasecmp(path, "rrset/name/", 11) == 0) {
		val = path + 11;
	} else if (strncasecmp(path, "rdata/name/", 11) == 0) {
		val = path + 11;
	} else if (strncasecmp(path, "rdata/ip/", 9) == 0) {
		val = path + 9;
	} else
		abort();
	if (strchr(val, '/') != NULL) {
		fprintf(stderr, "qualifiers not supported by CIRCL pDNS: %s\n",
			val);
		my_exit(1, NULL);
	}
	x = asprintf(&ret, "%s/%s", circl_server, val);
	if (x < 0)
		my_panic("asprintf");

	/* because we will NOT append query parameters,
	 * tell the caller to use ? for its query parameters.
	 */
	if (sep != NULL)
		*sep = '?';

	return (ret);
}

static void
circl_auth(reader_t reader) {
	if (reader->easy != NULL) {
		curl_easy_setopt(reader->easy, CURLOPT_USERPWD,
				 circl_authinfo);
		curl_easy_setopt(reader->easy, CURLOPT_HTTPAUTH,
				 CURLAUTH_BASIC);
	}
}

