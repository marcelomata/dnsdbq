
static char *deteque_token = NULL;
static char *deteque_server = NULL;
static char *deteque_authinfo = NULL;
static char *deteque_authfile = NULL;

static char *
deteque_url(const char *path, char *sep) {
	mode_e mode;
	const char *val = NULL, *scheme_if_needed;
	char *command;
	char *rrtype = NULL;
	char *bailiwick = NULL;
	char *nm = NULL;
	char *ret = NULL;
	int x;

	if (deteque_server == NULL) {
		deteque_server = strdup(sys->server);
	}

	if (strncasecmp(path, "rrset/name/", 11) == 0) {
		mode = rdata_mode;
		/* name/rrtype/bailiwick */
		val = path + 11;
		if ( (rrtype = strchr(val, '/')) != NULL) {
			*rrtype = '\0';
			rrtype++;
		}
		if ( rrtype && (bailiwick = strchr(rrtype, '/')) != NULL) {
			*bailiwick = '\0';
			bailiwick++;
		}
	} else if (strncasecmp(path, "rdata/name/", 11) == 0) {
		mode = name_mode;
		/* name/rrtype */
		val = path + 11;
		if ( (rrtype = strchr(val, '/')) != NULL) {
			*rrtype = '\0';
			rrtype++;
		}
	} else if (strncasecmp(path, "rdata/ip/", 9) == 0) {
		mode = ip_mode;
		/* ip,netmask */
		val = path + 9;
		if ( (nm = strchr(val, '/')) != NULL) {
			*nm = '\0';
			nm++;
		}
	} else if (strncasecmp(path, "rdata/raw/", 10) == 0) {
		mode = raw_mode;
		/* data/rrtype */
		val = path + 10;
		if ( (rrtype = strchr(val, '/')) != NULL) {
			*rrtype = '\0';
			rrtype++;
		}
	} else if (strncasecmp(path, "limits", 6) == 0) {
		mode = no_mode;
		val = path;
	} else {
		abort();
	}

	switch (mode) {
		case rdata_mode:
			if (rrtype != NULL)
				x = asprintf(&command, "_search/rrset/%s/%s",
					     val, rrtype);
			else
				x = asprintf(&command, "_search/rrset/%s/ANY",
					     val);
			if (x < 0)
				my_panic("asprintf");
			break;
		case name_mode:
			if (rrtype != NULL)
				x = asprintf(&command, "_search/rdata/%s/%s",
					     val, rrtype);
			else
				x = asprintf(&command, "_search/rdata/%s/ANY",
					     val);
			if (x < 0)
				my_panic("asprintf");
			break;
		case ip_mode:
			if (nm != NULL)
				x = asprintf(&command, "_search/rdata/%s%%2F%s",
					     val, nm);
			else
				x = asprintf(&command, "_search/rdata/%s",
					     val);
			if (x < 0)
				my_panic("asprintf");
			break;
		case raw_mode:
			fprintf(stderr, "Raw mode not yet supported by the deteque engine.\n");
			abort();
		case no_mode:
			x = asprintf(&command, "%s",
				     val);
			break;
		default:
			abort();
			break;
	}

	if (debuglev > 0) {
		fprintf(stderr, "%s -> %d %s*%s*%s\n", __FUNCTION__, mode, val, rrtype, bailiwick);
		fprintf(stderr, "%s -> %s\n", __FUNCTION__, command);
	}

	/* if the config file didn't specify our server, do it here. */
	if (deteque_server == NULL)
		deteque_server = strdup(sys->server);
	assert(deteque_server != NULL);

	/* supply a scheme if the server string did not. */
	scheme_if_needed = "";
	if (strstr(deteque_server, "://") == NULL)
		scheme_if_needed = "https://";

	/* assist passive operators in understanding their client mix. */
	x = asprintf(&ret, "%s%s/%s?swclient=%s&version=%s",
		     scheme_if_needed, deteque_server, command,
		     id_swclient, id_version);
	if (x < 0) {
		perror("asprintf");
		ret = NULL;
	}

	/* because we append query parameters, tell the caller to use & for
	 * any further query parameters.
	 */
	if (sep != NULL)
		*sep = '&';

	return (ret);
}

static void
deteque_request_info(void) {
	writer_t writer;

	if (debuglev > 0)
		fprintf(stderr, "deteque_request_info()\n");

	// start a writer, which might be format functions, or POSIX sort.
	writer = writer_init(0, 0);

	// start a status fetch.
	launch_one(writer, deteque_url("limits", NULL));
	
	// run all jobs to completion.
	io_engine(0);

	// stop the writer, which might involve reading POSIX sort's output.
	writer_fini(writer);
}

static inline const char* get_string(json_t *obj, const char *field) {
	json_t *of = json_object_get(obj, field);
	if (of != NULL ) {
	    return json_string_value(of);
	}
	return "n.d.";
}

static inline long get_int(json_t *obj, const char *field) {
	json_t *of = json_object_get(obj, field);
	if (of != NULL ) {
	    return (long) json_integer_value(of);
	}
	return -1;
}

static void
deteque_write_info(reader_t reader) {
	assert(reader);

	if (pres == present_text) {
		json_error_t error;
		json_t *root, *obj;

		root = json_loadb(reader->buf, reader->len, 0, &error);
		if (root == NULL) {
			fprintf(stderr, "%d:%d: %s %s\n",
				error.line, error.column,
				error.text, error.source);
			abort();
		}

		obj = json_object_get(root, "account");
		assert(obj);

		fprintf(stdout, "Account: %s\n", get_string(obj, "id") );

		obj = json_object_get(root, "limits");
		fprintf(stdout, " daily limit:  %ld\n", get_int(obj, "qpd") );
		fprintf(stdout, " montly limit: %ld\n", get_int(obj, "qpm") );

		obj = json_object_get(root, "current");
		fprintf(stdout, " daily usage:  %ld\n", get_int(obj, "qpd") );
		fprintf(stdout, " montly usage: %ld\n", get_int(obj, "qpm") );
	} else if (pres == present_json) {
		fwrite(reader->buf, 1, reader->len, stdout);
	} else {
		abort();
	}
}

/* ************************************************************************ */

struct response_data_s {
	char *memory;
	size_t size;
};

static size_t
get_payload_cb(void *contents, size_t size, size_t nmemb, void *userp) {
	size_t realsize = size * nmemb;
	struct response_data_s *mem = (struct response_data_s *)userp;

	char *ptr = realloc(mem->memory, mem->size + realsize + 1);
	if(ptr == NULL) {
		/* out of memory! */
		fprintf(stderr, "not enough memory (realloc returned NULL)\n");
		abort();
	}

	mem->memory = ptr;
	memcpy(&(mem->memory[mem->size]), contents, realsize);
	mem->size += realsize;
	mem->memory[mem->size] = 0;

	return realsize;
}

static char *store_token(const char *js) {
	const char *t;
	char *ret;
	long e;
	json_error_t error;
	json_t *root;
	FILE *f;

	if ( deteque_authfile == NULL ) {
		fprintf(stderr, "You need to specify an authfile to keep the temporary token data\n");
		abort();
	}

	root = json_loadb(js, strlen(js), 0, &error);
	if (root == NULL) {
		fprintf(stderr, "%d:%d: %s %s\n",
			error.line, error.column,
			error.text, error.source);
		abort();
	}

	t = get_string(root, "token");
	if ( t == NULL ) {
	    return NULL;
	}

	e = get_int(root, "expires");

	f = fopen(deteque_authfile, "w");
	if ( f == NULL ) {
	    return NULL;
	}
	fseek (f, 0, SEEK_SET);
	fprintf(f, "%s\n%ld\n", t, e);
	fclose(f);

	ret = strdup(t);

	json_decref(root);

	return ret;
}

static char *request_token(void) {
	char *user, *pass;
	json_t *root;
	char *js;
	char *token = NULL;

	if ( deteque_authinfo == NULL ) {
		return NULL;
	}

	user = deteque_authinfo;
	pass = strchr(user, ':');
	if ( pass != NULL ) {
		*pass = '\0';
		pass++;
	}

	if ( user == NULL || pass == NULL || *user == '\0' || *pass == '\0' ) {
		return NULL;
	}

	root = json_object();
	json_object_set_new( root, "username", json_string(user) );
	json_object_set_new( root, "password", json_string(pass) );

	js = json_dumps(root, 0);

	if ( js != NULL ) {
		CURL *easy;
		CURLcode res;
		struct curl_slist *headers = NULL;
		struct response_data_s payload;

		payload.memory = malloc(1);  /* will be grown as needed by the realloc above */
		payload.size = 0;    /* no data at this point */

		easy = curl_easy_init();
		if (easy == NULL ) {
			abort();
		}

		headers = curl_slist_append(headers, "Content-Type: application/json");

		curl_easy_setopt(easy, CURLOPT_URL, "https://api-pdnsbeta.deteque.com/v2/login/");
		curl_easy_setopt(easy, CURLOPT_POST, 1L);
		curl_easy_setopt(easy, CURLOPT_POSTFIELDS, js);
		curl_easy_setopt(easy, CURLOPT_SSL_VERIFYPEER, 0L);
		curl_easy_setopt(easy, CURLOPT_SSL_VERIFYHOST, 0L);
		curl_easy_setopt(easy, CURLOPT_HTTPHEADER, headers);

		curl_easy_setopt(easy, CURLOPT_WRITEFUNCTION, get_payload_cb);
		curl_easy_setopt(easy, CURLOPT_WRITEDATA, (void *) &payload);

		if (debuglev > 2)
			curl_easy_setopt(easy, CURLOPT_VERBOSE, 1L);
		res = curl_easy_perform(easy);

		if(res != CURLE_OK) {
			fprintf(stderr, "auth request failed failed: %s\n", curl_easy_strerror(res));
		}
		else {
			token = store_token(payload.memory);
		}

		curl_easy_cleanup(easy);
		curl_slist_free_all(headers);

		free(payload.memory);
	}

	return token;
}

static char *load_token(void) {
	char *expire;
	long lexp = 0;

	if ( deteque_authfile == NULL ) {
		return NULL;
	}

	if (debuglev > 0)
		fprintf(stderr, "%s: token file is %s\n", __FUNCTION__, deteque_authfile);

	FILE *f = fopen (deteque_authfile, "rb");
	if (f != NULL) {
		long length;

		fseek (f, 0, SEEK_END);
		length = ftell (f);
		if ( length < 0 ) {
			fclose (f);
			return NULL;
		}
		fseek (f, 0, SEEK_SET);

		deteque_token = malloc((size_t)length);
		if (deteque_token) {
			char *c;

			fread(deteque_token, 1, (size_t) length, f);
			expire = strchr(deteque_token, '\n');
			if ( expire != NULL ) {
			    *expire = '\0';
			    expire++;
			}
			c = strchr(deteque_token, '\r');
			if ( c != NULL ) {
			    *c = '\0';
			}
		}

		fclose (f);
	}

	if ( expire != NULL ) {
	    lexp = atol(expire);
	}

	/* If it's almost expired, then renew it by returning NULL */
	if ( lexp - 60 < time(NULL ) ) {
	    if ( deteque_token != NULL ) {
		free(deteque_token);
		return NULL;
	    }
	}

	return deteque_token;
}


/* ************************************************************************ */

static void
deteque_auth(reader_t reader) {
	assert(reader);

	reader->hdrs = curl_slist_append(reader->hdrs, "X-draft-cof: true");

	if ( deteque_token != NULL ) {
		char *header;

		/* If we have an explicit token, let's use it */
		if (asprintf(&header, "Authorization: Bearer %s", deteque_token) < 0) {
			my_panic("asprintf");
		}
		reader->hdrs = curl_slist_append(reader->hdrs, header);
		DESTROY(header);
	}
	else if ( (deteque_token = load_token()) != NULL ) {
		char *header;

		/* Otherwise load it from the file. If it's expired the token will be null */
		if (asprintf(&header, "Authorization: Bearer %s", deteque_token) < 0) {
			my_panic("asprintf");
		}
		reader->hdrs = curl_slist_append(reader->hdrs, header);
		DESTROY(header);
	}
	else if ( (deteque_token = request_token()) != NULL ) {
		char *header;

		/* If the token is expired or not set, request a new one */
		if (asprintf(&header, "Authorization: Bearer %s", deteque_token) < 0) {
			my_panic("asprintf");
		}
		reader->hdrs = curl_slist_append(reader->hdrs, header);
		DESTROY(header);
	}
	else {
		fprintf(stderr, "%s: No way to get a valid authentication token\n", __FUNCTION__);
		abort();
	}
}
