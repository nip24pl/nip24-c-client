/**
 * Copyright 2015-2025 NETCAT (www.netcat.pl)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * @author NETCAT <firma@netcat.pl>
 * @copyright 2015-2025 NETCAT (www.netcat.pl)
 * @license http://www.apache.org/licenses/LICENSE-2.0
 */

#include "internal.h"
#include "nip24.h"


/**
 * Zwraca losowy ciag w postaci heksadecymalnej
 * @param length zadana dlugosc ciagu
 * @param bstr adres na zwrocony ciag
 * @return TRUE jezeli OK, FALSE w przypadku bledu
 */
static BOOL _nip24_get_random(int length, BSTR* bstr)
{
	HCRYPTPROV hcp = 0;

	BOOL ret = FALSE;

	DWORD len;

	char hex[MAX_STRING];
	char buf[MAX_NUMBER];

	memset(hex, 0, sizeof(hex));

	if (!CryptAcquireContext(&hcp, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
		goto err;
	}

	if (!CryptGenRandom(hcp, length / 2, buf)) {
		goto err;
	}

	len = sizeof(hex);

	if (!CryptBinaryToString(buf, length / 2, CRYPT_STRING_HEXRAW | CRYPT_STRING_NOCRLF, hex, &len)) {
		goto err;
	}

	if (!utf8_to_bstr(hex, bstr)) {
		goto err;
	}

	// ok
	ret = TRUE;

err:
	CryptReleaseContext(hcp, 0);

	return ret;
}

/**
 * Oblicza HMAC z podanego ciagu
 * @param nip24 obiekt klienta
 * @param str ciag wejsciowy
 * @param bstr adres na obliczony HMAC jako ciag base64
 * @return TRUE jezeli OK, FALSE w przypadku bledu
 */
static BOOL _nip24_get_hmac(NIP24Client* nip24, const char* str, BSTR* bstr)
{
	HMAC_INFO hi;
	KEYDATA kd;

	HCRYPTPROV hcp = 0;
	HCRYPTKEY hck = 0;
	HCRYPTHASH hch = 0;

	BOOL ret = FALSE;

	DWORD blen;
	DWORD len;

	char hmac[MAX_STRING];
	char b64[MAX_STRING];

	if (!CryptAcquireContext(&hcp, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
		goto err;
	}

	kd.hdr.bType = PLAINTEXTKEYBLOB;
	kd.hdr.bVersion = CUR_BLOB_VERSION;
	kd.hdr.reserved = 0;
	kd.hdr.aiKeyAlg = CALG_RC2;
	kd.keyLength = (unsigned long)strlen(nip24->key);
	
	memcpy(kd.key, nip24->key, kd.keyLength);

	if (!CryptImportKey(hcp, (BYTE*)&kd, sizeof(kd), 0, CRYPT_IPSEC_HMAC_KEY, &hck)) {
		goto err;
	}

	if (!CryptCreateHash(hcp, CALG_HMAC, hck, 0, &hch)) {
		goto err;
	}

	memset(&hi, 0, sizeof(hi));
	hi.HashAlgid = CALG_SHA_256;

	if (!CryptSetHashParam(hch, HP_HMAC_INFO, (BYTE*)&hi, 0)) {
		goto err;
	}

	if (!CryptHashData(hch, (BYTE*)str, (DWORD)strlen(str), 0)) {
		goto err;
	}

	len = sizeof(hmac);

	if (!CryptGetHashParam(hch, HP_HASHVAL, hmac, &len, 0)) {
		goto err;
	}

	blen = sizeof(b64);

	if (!CryptBinaryToString(hmac, len, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, b64, &blen)) {
		goto err;
	}

	if (!utf8_to_bstr(b64, bstr)) {
		goto err;
	}

	// ok
	ret = TRUE;

err:
	CryptDestroyHash(hch);
	CryptDestroyKey(hck);
	CryptReleaseContext(hcp, 0);

	return ret;
}

/**
 * Przygotowanie naglowka z danymi do autoryzacji zapytania
 * @param nip24 obiekt klienta
 * @param method metoda HTTP
 * @param url docelowy adres URL
 * @param bstr adres na przygotowany naglowek
 * @return TRUE jezeli OK, FALSE w przypadku bledu
 */
static BOOL _nip24_get_auth_header(NIP24Client* nip24, BSTR method, BSTR url, BSTR* bstr)
{
	URL_COMPONENTS uc;

	BSTR host = NULL;
	BSTR path = NULL;
	BSTR nonce = NULL;
	BSTR hmac = NULL;

	BOOL ret = FALSE;

	char str[MAX_STRING];

	long ts;

	memset(&uc, 0, sizeof(uc));
	uc.dwStructSize = sizeof(uc);
	uc.dwSchemeLength = -1;
	uc.dwHostNameLength = -1;
	uc.dwUrlPathLength = -1;
	uc.dwExtraInfoLength = -1;

	if (!WinHttpCrackUrl(url, 0, 0, &uc)) {
		goto err;
	}

	host = SysAllocStringLen(uc.lpszHostName, uc.dwHostNameLength);
	path = SysAllocStringLen(uc.lpszUrlPath, uc.dwUrlPathLength);

	if (!_nip24_get_random(8, &nonce)) {
		goto err;
	}

	ts = (long)time(NULL);

	snprintf(str, sizeof(str), "%ld\n%ls\n%ls\n%ls\n%ls\n%d\n\n", ts, nonce, method, path, host, uc.nPort);

	if (!_nip24_get_hmac(nip24, str, &hmac)) {
		goto err;
	}

	snprintf(str, sizeof(str), "MAC id=\"%s\", ts=\"%ld\", nonce=\"%ls\", mac=\"%ls\"", nip24->id, ts, nonce, hmac);

	if (!utf8_to_bstr(str, bstr)) {
		goto err;
	}

	// ok
	ret = TRUE;

err:
	SysFreeString(host);
	SysFreeString(path);
	SysFreeString(nonce);
	SysFreeString(hmac);

	return ret;
}

/**
 * Przygotowanie naglowka z danymi o kliencie
 * @param nip24 obiekt klienta
 * @param bstr adres na przygotowany naglowek
 * @return TRUE jezeli OK, FALSE w przypadku bledu
 */
static BOOL _nip24_get_agent_header(NIP24Client* nip24, BSTR* bstr)
{
	char str[MAX_STRING];

	if (nip24->app && strlen(nip24->app) > 0) {
		snprintf(str, sizeof(str), "%s NIP24Client/%s C/%s", nip24->app, NIP24_VERSION, "Windows");
	}
	else {
		snprintf(str, sizeof(str), "NIP24Client/%s C/%s", NIP24_VERSION, "Windows");
	}

	return utf8_to_bstr(str, bstr);
}

/**
 * Parsowanie odpowiedzi serwera jako XML
 * @param str ciag z odpowiedzia serwera
 * @param adres na obiekt dokumentu XML
 * @return TRUE jezeli OK, FALSE w przypadku bledu
 */
static BOOL _nip24_load_doc(BSTR str, IXMLDOMDocument2** doc)
{
	IXMLDOMDocument2* pDoc = NULL;

	VARIANT_BOOL loaded;
	VARIANT xpath;
	HRESULT hr;

	BOOL ret = FALSE;

	if ((hr = CoCreateInstance(&CLSID_DOMDocument, 0, CLSCTX_INPROC_SERVER, &IID_IXMLDOMDocument2, &pDoc)) != S_OK) {
		goto err;
	}

	if ((hr = pDoc->lpVtbl->put_async(pDoc, VARIANT_FALSE)) != S_OK) {
		goto err;
	}

	if ((hr = pDoc->lpVtbl->put_validateOnParse(pDoc, VARIANT_FALSE)) != S_OK) {
		goto err;
	}

	xpath.vt = VT_BSTR;
	xpath.bstrVal = L"XPath";

	if ((hr = pDoc->lpVtbl->setProperty(pDoc, L"SelectionLanguage", xpath)) != S_OK) {
		goto err;
	}

	if ((hr = pDoc->lpVtbl->loadXML(pDoc, str, &loaded)) != S_OK || loaded != VARIANT_TRUE) {
		goto err;
	}

	// ok
	*doc = pDoc;
	pDoc = NULL;

	ret = TRUE;

err:
	if (pDoc) {
		pDoc->lpVtbl->Release(pDoc);
	}

	return ret;
}

/**
 * Metoda HTTP GET
 * @param nip24 obiekt klienta
 * @param url adres URL
 * @param adres na obiekt dokumentu XML
 * @return TRUE jezeli OK, FALSE w przypadku bledu
 */
static BOOL _nip24_http_get(NIP24Client* nip24, const char* url, IXMLDOMDocument2** doc)
{
	IXMLHTTPRequest* pXhr = NULL;

	VARIANT async;
	VARIANT var;
	HRESULT hr;
	
	BSTR burl = NULL;
	BSTR auth = NULL;
	BSTR agent = NULL;
	BSTR resp = NULL;

	BOOL ret = FALSE;

	long state;
	long status;

	// clear

	// xml http object
	if ((hr = CoCreateInstance(&CLSID_XMLHTTPRequest, 0, CLSCTX_INPROC_SERVER, &IID_IXMLHTTPRequest, &pXhr)) != S_OK) {
		goto err;
	}

	// send
	async.vt = VT_BOOL;
	async.boolVal = VARIANT_FALSE;

	var.vt = VT_BSTR;
	var.bstrVal = NULL;

	if (!utf8_to_bstr(url, &burl)) {
		goto err;
	}

	if ((hr = pXhr->lpVtbl->open(pXhr, L"GET", burl, async, var, var)) != S_OK) {
		goto err;
	}

	if ((hr = pXhr->lpVtbl->setRequestHeader(pXhr, L"Accept", L"application/xml")) != S_OK) {
		goto err;
	}

	if (!_nip24_get_auth_header(nip24, L"GET", burl, &auth)) {
		goto err;
	}

	if ((hr = pXhr->lpVtbl->setRequestHeader(pXhr, L"Authorization", auth)) != S_OK) {
		goto err;
	}

	if (!_nip24_get_agent_header(nip24, &agent)) {
		goto err;
	}

	if ((hr = pXhr->lpVtbl->setRequestHeader(pXhr, L"User-Agent", agent)) != S_OK) {
		goto err;
	}

	if ((hr = pXhr->lpVtbl->send(pXhr, var)) != S_OK) {
		goto err;
	}

	// check response
	if ((hr = pXhr->lpVtbl->get_readyState(pXhr, &state)) != S_OK) {
		goto err;
	}

	if ((hr = pXhr->lpVtbl->get_status(pXhr, &status)) != S_OK) {
		goto err;
	}

	if (state != 4 || status != 200) {
		goto err;
	}

	if ((hr = pXhr->lpVtbl->get_responseText(pXhr, &resp)) != S_OK) {
		goto err;
	}

	if (!_nip24_load_doc(resp, doc)) {
		goto err;
	}

	// ok
	ret = TRUE;

err:
	if (pXhr) {
		pXhr->lpVtbl->Release(pXhr);
	}

	SysFreeString(burl);
	SysFreeString(auth);
	SysFreeString(agent);
	SysFreeString(resp);

	return ret;
}

/**
 * Wyzerowanie ostatniego bledu
 * @param nip24 obiekt klienta
 */
static void _nip24_clear_err(NIP24Client* nip24)
{
	nip24->err_code = 0;

	free(nip24->err);
	nip24->err = NULL;
}

/**
 * Ustawienie komunikatu bledu
 * @param nip24 obiekt klienta
 * @param code kod bledu
 * @param err komunikat
 */
static void _nip24_set_err(NIP24Client* nip24, int code, const char* err)
{
	_nip24_clear_err(nip24);

	nip24->err_code = code;
	nip24->err = strdup(err ? err : nip24_errstr(code));
}

/**
 * Pobranie sufiksu sciezki
 * @param nip24 obiekt klienta
 * @param type typ numeru identyfikujacego firme
 * @param number numer okreslonego typu
 * @param path adres bufora do ktorego zostanie dodana przygotowana sciezka
 * @return TRUE jezeli OK, FALSE w przypadku bledu
 */
static BOOL _nip24_get_path_suffix(NIP24Client* nip24, Number type, const char* number, char* path)
{
	char iban_str[MAX_STRING];

	char* n = NULL;

	if (type == NIP) {
		if (!nip24_nip_is_valid(number)) {
			_nip24_set_err(nip24, NIP24_ERR_CLI_NIP, NULL);
			return FALSE;
		}

		n = nip24_nip_normalize(number);

		strcat(path, "nip/");
		strcat(path, n);

		free(n);
	}
	else if (type == REGON) {
		if (!nip24_regon_is_valid(number)) {
			_nip24_set_err(nip24, NIP24_ERR_CLI_REGON, NULL);
			return FALSE;
		}

		n = nip24_regon_normalize(number);

		strcat(path, "regon/");
		strcat(path, n);

		free(n);
	}
	else if (type == KRS) {
		if (!nip24_krs_is_valid(number)) {
			_nip24_set_err(nip24, NIP24_ERR_CLI_KRS, NULL);
			return FALSE;
		}

		n = nip24_krs_normalize(number);

		strcat(path, "krs/");
		strcat(path, n);

		free(n);
	}
	else if (type == EUVAT) {
		if (!nip24_euvat_is_valid(number)) {
			_nip24_set_err(nip24, NIP24_ERR_CLI_EUVAT, NULL);
			return FALSE;
		}

		n = nip24_euvat_normalize(number);

		strcat(path, "euvat/");
		strcat(path, n);

		free(n);
	}
	else if (type == IBAN) {
		snprintf(iban_str, sizeof(iban_str), "%s", number);

		if (!nip24_iban_is_valid(iban_str)) {
			snprintf(iban_str, sizeof(iban_str), "PL%s", number);

			if (!nip24_iban_is_valid(iban_str)) {
				_nip24_set_err(nip24, NIP24_ERR_CLI_IBAN, NULL);
				return FALSE;
			}
		}

		n = nip24_iban_normalize(iban_str);

		strcat(path, "iban/");
		strcat(path, n);

		free(n);
	}
	else {
		_nip24_set_err(nip24, NIP24_ERR_CLI_NUMBER, NULL);
		return FALSE;
	}

	return TRUE;
}

/**
 * Pobranie wartosci elementu z dokumentu
 * @param doc obiekt dokumentu XML
 * @param xpath sciezka do elementu
 * @param def wartosc domyslna zwracana w przypadku braku elementu
 * @return wartosc elementu
 */
static char* _nip24_parse_str(IXMLDOMDocument2* doc, BSTR xpath, const char* def)
{
	IXMLDOMElement* root = NULL;
	IXMLDOMNode* node = NULL;

	BSTR txt = NULL;

	HRESULT hr;

	char* str = NULL;

	if ((hr = doc->lpVtbl->get_documentElement(doc, &root)) != S_OK) {
		goto err;
	}

	if ((hr = root->lpVtbl->selectSingleNode(root, xpath, &node)) != S_OK) {
		goto err;
	}

	if ((hr = node->lpVtbl->get_text(node, &txt)) != S_OK) {
		goto err;
	}

	if (txt && wcslen(txt) > 0) {
		bstr_replace(&txt, L"&quot;", L"\"");
		bstr_replace(&txt, L"&quot;", L"\"");
		bstr_replace(&txt, L"&apos;", L"'");
		bstr_replace(&txt, L"&lt;", L"<");
		bstr_replace(&txt, L"&gt;", L">");
		bstr_replace(&txt, L"&amp;", L"&");
	}

	if (!bstr_to_utf8(txt, &str)) {
		goto err;
	}
	
err:
	if (!str) {
		str = strdup(def ? def : "");
	}

	if (node) {
		node->lpVtbl->Release(node);
	}

	if (root) {
		root->lpVtbl->Release(root);
	}

	SysFreeString(txt);

	return str;
}

/**
 * Pobranie wartosci elementu z dokumentu
 * @param doc obiekt dokumentu XML
 * @param xpath sciezka do elementu
 * @return wartosc elementu lub 0 jezeli brak elementu
 */
static time_t _nip24_parse_datetime(IXMLDOMDocument2* doc, BSTR xpath)
{
	struct tm stm;

	char* str = _nip24_parse_str(doc, xpath, NULL);

	time_t t = 0;

	// 2010-04-11T23:02:46.453+02:00
	if (str && strlen(str) > 0) {
		memset(&stm, 0, sizeof(stm));
		
		if (sscanf(str, "%04d-%02d-%02dT%02d:%02d:%02d", &stm.tm_year, &stm.tm_mon, &stm.tm_mday,
			&stm.tm_hour, &stm.tm_min, &stm.tm_sec) != 6) {

			goto err;
		}

		stm.tm_year -= 1900;
		stm.tm_mon -= 1;

		t = _mkgmtime(&stm);
	}

err:
	free(str);

	return t;
}

/**
 * Pobranie wartosci elementu z dokumentu
 * @param doc obiekt dokumentu XML
 * @param xpath sciezka do elementu
 * @return wartosc elementu lub 0 jezeli brak elementu
 */
static time_t _nip24_parse_date(IXMLDOMDocument2* doc, BSTR xpath)
{
	struct tm stm;

	char* str = _nip24_parse_str(doc, xpath, NULL);

	time_t t = 0;

	// 2019-02-13+01:00
	if (str && strlen(str) > 0) {
		memset(&stm, 0, sizeof(stm));
		
		if (sscanf(str, "%04d-%02d-%02d", &stm.tm_year, &stm.tm_mon, &stm.tm_mday) != 3) {
			goto err;
		}

		stm.tm_year -= 1900;
		stm.tm_mon -= 1;

		t = _mkgmtime(&stm);
	}

err:
	free(str);

	return t;
}

/**
 * Pobranie wartosci elementu z dokumentu
 * @param doc obiekt dokumentu XML
 * @param xpath sciezka do elementu
 * @param def wartosc domyslna zwracana w przypadku braku elementu
 * @return wartosc elementu
 */
static int _nip24_parse_int(IXMLDOMDocument2* doc, BSTR xpath, int def)
{
	int val = def;

	char* str = _nip24_parse_str(doc, xpath, NULL);

	if (str && strlen(str) > 0) {
		val = atoi(str);
	}

	free(str);

	return val;
}

/**
 * Pobranie wartosci elementu z dokumentu
 * @param doc obiekt dokumentu XML
 * @param xpath sciezka do elementu
 * @param def wartosc domyslna zwracana w przypadku braku elementu
 * @return wartosc elementu
 */
static double _nip24_parse_double(IXMLDOMDocument2* doc, BSTR xpath, double def)
{
	double val = def;

	char* str = _nip24_parse_str(doc, xpath, NULL);

	if (str && strlen(str) > 0) {
		val = atof(str);
	}

	free(str);

	return val;
}

/**
 * Pobranie wartosci elementu z dokumentu
 * @param doc obiekt dokumentu XML
 * @param xpath sciezka do elementu
 * @param def wartosc domyslna zwracana w przypadku braku elementu
 * @return wartosc elementu
 */
static BOOL _nip24_parse_bool(IXMLDOMDocument2* doc, BSTR xpath, BOOL def)
{
	BOOL val = def;

	char* str = _nip24_parse_str(doc, xpath, NULL);

	if (str && strlen(str) > 0) {
		val = (strcmp(str, "true") == 0 ? TRUE : FALSE);
	}

	free(str);

	return val;
}

/**
 * Dodanie wartoœci wêz³a XML jako obiektu VATPerson do podanej listy
 * @param doc obiekt dokumentu XML
 * @param prefix sciezka do elementu
 * @param list adres listy osób
 * @param count adres na iloœæ elementów listy
 */
static void _nip24_parse_vatperson(IXMLDOMDocument2* doc, BSTR prefix, VATPerson*** list, int* count)
{
	VATPerson* vp = NULL;

	wchar_t xpath[MAX_STRING];

	char* str = NULL;

	int i;

	for (i = 1; ; i++) {
		_snwprintf(xpath, MAX_STRING, L"%s/person[%d]/nip", prefix, i);
		str = _nip24_parse_str(doc, xpath, NULL);

		if (!str || strlen(str) == 0) {
			break;
		}

		if (!vatperson_new(&vp)) {
			goto err;
		}

		vp->NIP = str;
		str = NULL;

		_snwprintf(xpath, MAX_STRING, L"%s/person[%d]/companyName", prefix, i);
		vp->CompanyName = _nip24_parse_str(doc, xpath, NULL);

		_snwprintf(xpath, MAX_STRING, L"%s/person[%d]/firstName", prefix, i);
		vp->FirstName = _nip24_parse_str(doc, xpath, NULL);

		_snwprintf(xpath, MAX_STRING, L"%s/person[%d]/lastName", prefix, i);
		vp->LastName = _nip24_parse_str(doc, xpath, NULL);

		// add
		(*count)++;

		if (((*list) = (VATPerson**)realloc(*list, sizeof(VATPerson*) * (*count))) == NULL) {
			goto err;
		}

		(*list)[(*count) - 1] = vp;
		vp = NULL;
	}

err:
	vatperson_free(&vp);

	free(str);
}

/////////////////////////////////////////////////////////////////

NIP24_API BOOL nip24_new(NIP24Client** nip24, const char* url, const char* id, const char* key)
{
	NIP24Client* n = NULL;

	BOOL ret = FALSE;

	if (!nip24 || !url || strlen(url) == 0 || !id || strlen(id) == 0 || !key || strlen(key) == 0) {
		goto err;
	}

	if ((n = (NIP24Client*)malloc(sizeof(NIP24Client))) == NULL) {
		goto err;
	}

	memset(n, 0, sizeof(NIP24Client));

	n->url = strdup(url);
	n->id = strdup(id);
	n->key = strdup(key);

	// ok
	*nip24 = n;
	n = NULL;

	ret = TRUE;

err:
	nip24_free(&n);

	return ret;
}

NIP24_API BOOL nip24_new_prod(NIP24Client** nip24, const char* id, const char* key)
{
	return nip24_new(nip24, NIP24_PRODUCTION_URL, id, key);
}

NIP24_API BOOL nip24_new_test(NIP24Client** nip24)
{
	return nip24_new(nip24, NIP24_TEST_URL, NIP24_TEST_ID, NIP24_TEST_KEY);
}

NIP24_API void nip24_free(NIP24Client** nip24)
{
	NIP24Client* n = (nip24 ? *nip24 : NULL);

	if (n) {
		free(n->url);
		free(n->id);
		free(n->key);

		free(n->app);
		free(n->err);

		free(*nip24);
		*nip24 = NULL;
	}
}

NIP24_API int nip24_get_last_err_code(NIP24Client* nip24)
{
	return (nip24 ? nip24->err_code : -1);
}

NIP24_API char* nip24_get_last_err(NIP24Client* nip24)
{
	return (nip24 ? nip24->err : NULL);
}

NIP24_API BOOL nip24_is_active(NIP24Client* nip24, Number type, const char* number)
{
	IXMLDOMDocument2* doc = NULL;

	BOOL ret = FALSE;

	char url[MAX_STRING];

	char* code = NULL;

	if (!nip24 || type < NIP || type > EUVAT || !number || strlen(number) == 0) {
		_nip24_set_err(nip24, NIP24_ERR_CLI_INPUT, NULL);
		goto err;
	}

	// clear error
	_nip24_clear_err(nip24);

	// validate number and construct path
	snprintf(url, sizeof(url), "%s/check/firm/", nip24->url);

	if (!_nip24_get_path_suffix(nip24, type, number, url)) {
		goto err;
	}

	// prepare request
	if (!_nip24_http_get(nip24, url, &doc)) {
		_nip24_set_err(nip24, NIP24_ERR_CLI_CONNECT, NULL);
		goto err;
	}

	// parse response
	code = _nip24_parse_str(doc, L"/result/error/code", NULL);

	if (code && strlen(code) > 0) {
		if (strcmp(code, "9") == 0) {
			// not active
			_nip24_clear_err(nip24);
		}
		else {
			// error
			_nip24_set_err(nip24, atoi(code), _nip24_parse_str(doc, L"/result/error/description", NULL));
		}

		goto err;
	}

	// active
	ret = TRUE;

err:
	if (doc) {
		doc->lpVtbl->Release(doc);
	}

	free(code);

	return ret;
}

NIP24_API BOOL nip24_is_active_nip(NIP24Client* nip24, const char* nip)
{
	return nip24_is_active(nip24, NIP, nip);
}

NIP24_API InvoiceData* nip24_get_invoice_data(NIP24Client* nip24, Number type, const char* number, BOOL force)
{
	IXMLDOMDocument2* doc = NULL;
	InvoiceData* id = NULL;

	char url[MAX_STRING];

	char* code = NULL;

	if (!nip24 || type < NIP || type > EUVAT || !number || strlen(number) == 0) {
		_nip24_set_err(nip24, NIP24_ERR_CLI_INPUT, NULL);
		goto err;
	}

	// clear error
	_nip24_clear_err(nip24);

	// validate number and construct path
	snprintf(url, sizeof(url), "%s/get/invoice/", nip24->url);

	if (!_nip24_get_path_suffix(nip24, type, number, url)) {
		goto err;
	}

	// prepare request
	if (!_nip24_http_get(nip24, url, &doc)) {
		_nip24_set_err(nip24, NIP24_ERR_CLI_CONNECT, NULL);
		goto err;
	}

	// parse response
	code = _nip24_parse_str(doc, L"/result/error/code", NULL);

	if (code && strlen(code) > 0) {
		// error
		_nip24_set_err(nip24, atoi(code), _nip24_parse_str(doc, L"/result/error/description", NULL));
		goto err;
	}

	if (!invoicedata_new(&id)) {
		goto err;
	}

	id->UID = _nip24_parse_str(doc, L"/result/firm/uid", NULL);

	id->NIP = _nip24_parse_str(doc, L"/result/firm/nip", NULL);

	id->Name = _nip24_parse_str(doc, L"/result/firm/name", NULL);
	id->FirstName = _nip24_parse_str(doc, L"/result/firm/firstname", NULL);
	id->LastName = _nip24_parse_str(doc, L"/result/firm/lastname", NULL);

	id->Street = _nip24_parse_str(doc, L"/result/firm/street", NULL);
	id->StreetNumber = _nip24_parse_str(doc, L"/result/firm/streetNumber", NULL);
	id->HouseNumber = _nip24_parse_str(doc, L"/result/firm/houseNumber", NULL);
	id->City = _nip24_parse_str(doc, L"/result/firm/city", NULL);
	id->PostCode = _nip24_parse_str(doc, L"/result/firm/postCode", NULL);
	id->PostCity = _nip24_parse_str(doc, L"/result/firm/postCity", NULL);

	id->Phone = _nip24_parse_str(doc, L"/result/firm/phone", NULL);
	id->Email = _nip24_parse_str(doc, L"/result/firm/email", NULL);
	id->WWW = _nip24_parse_str(doc, L"/result/firm/www", NULL);

err:
	if (doc) {
		doc->lpVtbl->Release(doc);
	}

	free(code);

	return id;
}

NIP24_API InvoiceData* nip24_get_invoice_data_nip(NIP24Client* nip24, const char* nip, BOOL force)
{
	return nip24_get_invoice_data(nip24, NIP, nip, force);
}

NIP24_API AllData* nip24_get_all_data(NIP24Client* nip24, Number type, const char* number, BOOL force)
{
	IXMLDOMDocument2* doc = NULL;
	AllData* ad = NULL;
	BusinessPartner* bp = NULL;
	PKD* pkd = NULL;

	wchar_t xpath[MAX_STRING];
	char url[MAX_STRING];

	char* code = NULL;
	char* str = NULL;

	int i;

	if (!nip24 || type < NIP || type > EUVAT || !number || strlen(number) == 0) {
		_nip24_set_err(nip24, NIP24_ERR_CLI_INPUT, NULL);
		goto err;
	}

	// clear error
	_nip24_clear_err(nip24);

	// validate number and construct path
	snprintf(url, sizeof(url), "%s/get/all/", nip24->url);

	if (!_nip24_get_path_suffix(nip24, type, number, url)) {
		goto err;
	}

	// prepare request
	if (!_nip24_http_get(nip24, url, &doc)) {
		_nip24_set_err(nip24, NIP24_ERR_CLI_CONNECT, NULL);
		goto err;
	}

	// parse response
	code = _nip24_parse_str(doc, L"/result/error/code", NULL);

	if (code && strlen(code) > 0) {
		// error
		_nip24_set_err(nip24, atoi(code), _nip24_parse_str(doc, L"/result/error/description", NULL));
		goto err;
	}

	if (!alldata_new(&ad)) {
		goto err;
	}

	ad->UID = _nip24_parse_str(doc, L"/result/firm/uid", NULL);

	ad->Type = _nip24_parse_str(doc, L"/result/firm/type", NULL);
	ad->NIP = _nip24_parse_str(doc, L"/result/firm/nip", NULL);
	ad->REGON = _nip24_parse_str(doc, L"/result/firm/regon", NULL);

	ad->Name = _nip24_parse_str(doc, L"/result/firm/name", NULL);
	ad->ShortName = _nip24_parse_str(doc, L"/result/firm/shortname", NULL);
	ad->FirstName = _nip24_parse_str(doc, L"/result/firm/firstname", NULL);
	ad->SecondName = _nip24_parse_str(doc, L"/result/firm/secondname", NULL);
	ad->LastName = _nip24_parse_str(doc, L"/result/firm/lastname", NULL);

	ad->Street = _nip24_parse_str(doc, L"/result/firm/street", NULL);
	ad->StreetCode = _nip24_parse_str(doc, L"/result/firm/streetCode", NULL);
	ad->StreetNumber = _nip24_parse_str(doc, L"/result/firm/streetNumber", NULL);
	ad->HouseNumber = _nip24_parse_str(doc, L"/result/firm/houseNumber", NULL);
	ad->City = _nip24_parse_str(doc, L"/result/firm/city", NULL);
	ad->CityCode = _nip24_parse_str(doc, L"/result/firm/cityCode", NULL);
	ad->Community = _nip24_parse_str(doc, L"/result/firm/community", NULL);
	ad->CommunityCode = _nip24_parse_str(doc, L"/result/firm/communityCode", NULL);
	ad->County = _nip24_parse_str(doc, L"/result/firm/county", NULL);
	ad->CountyCode = _nip24_parse_str(doc, L"/result/firm/countyCode", NULL);
	ad->State = _nip24_parse_str(doc, L"/result/firm/state", NULL);
	ad->StateCode = _nip24_parse_str(doc, L"/result/firm/stateCode", NULL);
	ad->PostCode = _nip24_parse_str(doc, L"/result/firm/postCode", NULL);
	ad->PostCity = _nip24_parse_str(doc, L"/result/firm/postCity", NULL);

	ad->Phone = _nip24_parse_str(doc, L"/result/firm/phone", NULL);
	ad->Email = _nip24_parse_str(doc, L"/result/firm/email", NULL);
	ad->WWW = _nip24_parse_str(doc, L"/result/firm/www", NULL);

	ad->CreationDate = _nip24_parse_datetime(doc, L"/result/firm/creationDate");
	ad->StartDate = _nip24_parse_datetime(doc, L"/result/firm/startDate");
	ad->RegistrationDate = _nip24_parse_datetime(doc, L"/result/firm/registrationDate");
	ad->HoldDate = _nip24_parse_datetime(doc, L"/result/firm/holdDate");
	ad->RenevalDate = _nip24_parse_datetime(doc, L"/result/firm/renevalDate");
	ad->LastUpdateDate = _nip24_parse_datetime(doc, L"/result/firm/lastUpdateDate");
	ad->EndDate = _nip24_parse_datetime(doc, L"/result/firm/endDate");

	ad->RegistryEntityCode = _nip24_parse_str(doc, L"/result/firm/registryEntity/code", NULL);
	ad->RegistryEntityName = _nip24_parse_str(doc, L"/result/firm/registryEntity/name", NULL);

	ad->RegistryCode = _nip24_parse_str(doc, L"/result/firm/registry/code", NULL);
	ad->RegistryName = _nip24_parse_str(doc, L"/result/firm/registry/name", NULL);

	ad->RecordCreationDate = _nip24_parse_datetime(doc, L"/result/firm/record/created");
	ad->RecordNumber = _nip24_parse_str(doc, L"/result/firm/record/number", NULL);

	ad->BasicLegalFormCode = _nip24_parse_str(doc, L"/result/firm/basicLegalForm/code", NULL);
	ad->BasicLegalFormName = _nip24_parse_str(doc, L"/result/firm/basicLegalForm/name", NULL);

	ad->SpecificLegalFormCode = _nip24_parse_str(doc, L"/result/firm/specificLegalForm/code", NULL);
	ad->SpecificLegalFormName = _nip24_parse_str(doc, L"/result/firm/specificLegalForm/name", NULL);

	ad->OwnershipFormCode = _nip24_parse_str(doc, L"/result/firm/ownershipForm/code", NULL);
	ad->OwnershipFormName = _nip24_parse_str(doc, L"/result/firm/ownershipForm/name", NULL);

	for (i = 1; ; i++) {
		_snwprintf(xpath, MAX_STRING, L"/result/firm/businessPartners/businessPartner[%d]/regon", i);
		str = _nip24_parse_str(doc, xpath, NULL);

		if (!str || strlen(str) == 0) {
			break;
		}

		if (!businesspartner_new(&bp)) {
			alldata_free(&ad);
			goto err;
		}

		bp->REGON = str;
		str = NULL;

		_snwprintf(xpath, MAX_STRING, L"/result/firm/businessPartners/businessPartner[%d]/firmName", i);
		bp->FirmName = _nip24_parse_str(doc, xpath, NULL);

		_snwprintf(xpath, MAX_STRING, L"/result/firm/businessPartners/businessPartner[%d]/firstName", i);
		bp->FirstName = _nip24_parse_str(doc, xpath, NULL);

		_snwprintf(xpath, MAX_STRING, L"/result/firm/businessPartners/businessPartner[%d]/secondName", i);
		bp->SecondName = _nip24_parse_str(doc, xpath, NULL);

		_snwprintf(xpath, MAX_STRING, L"/result/firm/businessPartners/businessPartner[%d]/lastName", i);
		bp->LastName = _nip24_parse_str(doc, xpath, NULL);

		free(str);
		str = NULL;

		// add
		ad->BusinessPartnerCount++;

		if ((ad->BusinessPartner = (BusinessPartner**)realloc(ad->BusinessPartner, sizeof(BusinessPartner*) * ad->BusinessPartnerCount)) == NULL) {
			alldata_free(&ad);
			goto err;
		}

		ad->BusinessPartner[ad->BusinessPartnerCount - 1] = bp;
		bp = NULL;
	}

	for (i = 1; ; i++) {
		_snwprintf(xpath, MAX_STRING, L"/result/firm/PKDs/PKD[%d]/code", i);
		str = _nip24_parse_str(doc, xpath, NULL);

		if (!str || strlen(str) == 0) {
			break;
		}

		if (!pkd_new(&pkd)) {
			alldata_free(&ad);
			goto err;
		}

		pkd->Code = str;
		str = NULL;

		_snwprintf(xpath, MAX_STRING, L"/result/firm/PKDs/PKD[%d]/description", i);
		pkd->Description = _nip24_parse_str(doc, xpath, NULL);

		_snwprintf(xpath, MAX_STRING, L"/result/firm/PKDs/PKD[%d]/primary", i);
		str = _nip24_parse_str(doc, xpath, "false");
		pkd->Primary = (strcmp(str, "true") == 0 ? TRUE : FALSE);
		
		free(str);
		str = NULL;

		_snwprintf(xpath, MAX_STRING, L"/result/firm/PKDs/PKD[%d]/version", i);
		pkd->Version = _nip24_parse_str(doc, xpath, NULL);

		// add
		ad->PKDCount++;

		if ((ad->PKD = (PKD**)realloc(ad->PKD, sizeof(PKD*) * ad->PKDCount)) == NULL) {
			alldata_free(&ad);
			goto err;
		}
		
		ad->PKD[ad->PKDCount - 1] = pkd;
		pkd = NULL;
	}

err:
	if (doc) {
		doc->lpVtbl->Release(doc);
	}

	businesspartner_free(&bp);
	pkd_free(&pkd);

	free(code);
	free(str);

	return ad;
}

NIP24_API AllData* nip24_get_all_data_nip(NIP24Client* nip24, const char* nip, BOOL force)
{
	return nip24_get_all_data(nip24, NIP, nip, force);
}

NIP24_API VIESData* nip24_get_vies_data(NIP24Client* nip24, const char* euvat)
{
	IXMLDOMDocument2* doc = NULL;
	VIESData* vies = NULL;

	char url[MAX_STRING];

	char* code = NULL;

	if (!nip24 || !euvat || strlen(euvat) == 0) {
		_nip24_set_err(nip24, NIP24_ERR_CLI_INPUT, NULL);
		goto err;
	}

	// clear error
	_nip24_clear_err(nip24);

	// validate number and construct path
	snprintf(url, sizeof(url), "%s/get/vies/", nip24->url);

	if (!_nip24_get_path_suffix(nip24, EUVAT, euvat, url)) {
		goto err;
	}

	// prepare request
	if (!_nip24_http_get(nip24, url, &doc)) {
		_nip24_set_err(nip24, NIP24_ERR_CLI_CONNECT, NULL);
		goto err;
	}

	// parse response
	code = _nip24_parse_str(doc, L"/result/error/code", NULL);

	if (code && strlen(code) > 0) {
		// error
		_nip24_set_err(nip24, atoi(code), _nip24_parse_str(doc, L"/result/error/description", NULL));
		goto err;
	}

	if (!viesdata_new(&vies)) {
		goto err;
	}

	vies->UID = _nip24_parse_str(doc, L"/result/vies/uid", NULL);

	vies->CountryCode = _nip24_parse_str(doc, L"/result/vies/countryCode", NULL);
	vies->VATNumber = _nip24_parse_str(doc, L"/result/vies/vatNumber", NULL);

	vies->Valid = _nip24_parse_bool(doc, L"/result/vies/valid", FALSE);

	vies->TraderName = _nip24_parse_str(doc, L"/result/vies/traderName", NULL);
	vies->TraderCompanyType = _nip24_parse_str(doc, L"/result/vies/traderCompanyType", NULL);
	vies->TraderAddress = _nip24_parse_str(doc, L"/result/vies/traderAddress", NULL);

	vies->ID = _nip24_parse_str(doc, L"/result/vies/id", NULL);
	vies->Date = _nip24_parse_date(doc, L"/result/vies/date");
	vies->Source = _nip24_parse_str(doc, L"/result/vies/source", NULL);

err:
	if (doc) {
		doc->lpVtbl->Release(doc);
	}

	free(code);

	return vies;
}

NIP24_API VATStatus* nip24_get_vat_status(NIP24Client* nip24, Number type, const char* number, BOOL direct)
{
	IXMLDOMDocument2* doc = NULL;
	VATStatus* vat = NULL;

	char url[MAX_STRING];

	char* code = NULL;

	if (!nip24 || type < NIP || type > EUVAT || !number || strlen(number) == 0) {
		_nip24_set_err(nip24, NIP24_ERR_CLI_INPUT, NULL);
		goto err;
	}

	// clear error
	_nip24_clear_err(nip24);

	// validate number and construct path
	snprintf(url, sizeof(url), "%s/check/vat/direct/", nip24->url);

	if (!_nip24_get_path_suffix(nip24, type, number, url)) {
		goto err;
	}

	// prepare request
	if (!_nip24_http_get(nip24, url, &doc)) {
		_nip24_set_err(nip24, NIP24_ERR_CLI_CONNECT, NULL);
		goto err;
	}

	// parse response
	code = _nip24_parse_str(doc, L"/result/error/code", NULL);

	if (code && strlen(code) > 0) {
		// error
		_nip24_set_err(nip24, atoi(code), _nip24_parse_str(doc, L"/result/error/description", NULL));
		goto err;
	}

	if (!vatstatus_new(&vat)) {
		goto err;
	}

	vat->UID = _nip24_parse_str(doc, L"/result/vat/uid", NULL);

	vat->NIP = _nip24_parse_str(doc, L"/result/vat/nip", NULL);
	vat->REGON = _nip24_parse_str(doc, L"/result/vat/regon", NULL);
	vat->Name = _nip24_parse_str(doc, L"/result/vat/name", NULL);

	vat->Status = _nip24_parse_int(doc, L"/result/vat/status", 0);
	vat->Result = _nip24_parse_str(doc, L"/result/vat/result", NULL);

	vat->ID = _nip24_parse_str(doc, L"/result/vat/id", NULL);
	vat->Date = _nip24_parse_date(doc, L"/result/vat/date");
	vat->Source = _nip24_parse_str(doc, L"/result/vat/source", NULL);

err:
	if (doc) {
		doc->lpVtbl->Release(doc);
	}

	free(code);

	return vat;
}

NIP24_API VATStatus* nip24_get_vat_status_nip(NIP24Client* nip24, const char* nip, BOOL direct)
{
	return nip24_get_vat_status(nip24, NIP, nip, direct);
}

NIP24_API IBANStatus* nip24_get_iban_status(NIP24Client* nip24, Number type, const char* number, const char* iban, time_t date)
{
	IXMLDOMDocument2* doc = NULL;
	IBANStatus* is = NULL;

	char iban_str[MAX_STRING];
	char date_str[MAX_STRING];
	char url[MAX_STRING];

	char* code = NULL;
	char* ib = NULL;

	if (!nip24 || type < NIP || type > KRS || !number || strlen(number) == 0 || !iban || strlen(iban) == 0) {
		_nip24_set_err(nip24, NIP24_ERR_CLI_INPUT, NULL);
		goto err;
	}

	snprintf(iban_str, sizeof(iban_str), "%s", iban);

	if (!nip24_iban_is_valid(iban_str)) {
		snprintf(iban_str, sizeof(iban_str), "PL%s", iban);
	
		if (!nip24_iban_is_valid(iban_str)) {
			_nip24_set_err(nip24, NIP24_ERR_CLI_IBAN, NULL);
			goto err;
		}
	}

	ib = nip24_iban_normalize(iban_str);

	if (date <= 0) {
		date = time(NULL);
	}

	strftime(date_str, sizeof(date_str), "%Y-%m-%d", localtime(&date));

	// clear error
	_nip24_clear_err(nip24);

	// validate number and construct path
	snprintf(url, sizeof(url), "%s/check/iban/", nip24->url);

	if (!_nip24_get_path_suffix(nip24, type, number, url)) {
		goto err;
	}

	strcat_s(url, sizeof(url), "/");
	strcat_s(url, sizeof(url), ib);
	strcat_s(url, sizeof(url), "/");
	strcat_s(url, sizeof(url), date_str);

	// prepare request
	if (!_nip24_http_get(nip24, url, &doc)) {
		_nip24_set_err(nip24, NIP24_ERR_CLI_CONNECT, NULL);
		goto err;
	}

	// parse response
	code = _nip24_parse_str(doc, L"/result/error/code", NULL);

	if (code && strlen(code) > 0) {
		// error
		_nip24_set_err(nip24, atoi(code), _nip24_parse_str(doc, L"/result/error/description", NULL));
		goto err;
	}

	if (!ibanstatus_new(&is)) {
		goto err;
	}

	is->UID = _nip24_parse_str(doc, L"/result/iban/uid", NULL);

	is->NIP = _nip24_parse_str(doc, L"/result/iban/nip", NULL);
	is->REGON = _nip24_parse_str(doc, L"/result/iban/regon", NULL);
	is->IBAN = _nip24_parse_str(doc, L"/result/iban/iban", NULL);

	is->Valid = _nip24_parse_bool(doc, L"/result/iban/valid", FALSE);
	
	is->ID = _nip24_parse_str(doc, L"/result/iban/id", NULL);
	is->Date = _nip24_parse_date(doc, L"/result/iban/date");
	is->Source = _nip24_parse_str(doc, L"/result/iban/source", NULL);

err:
	if (doc) {
		doc->lpVtbl->Release(doc);
	}

	free(code);
	free(ib);

	return is;
}

NIP24_API IBANStatus* nip24_get_iban_status_nip(NIP24Client* nip24, const char* nip, const char* iban, time_t date)
{
	return nip24_get_iban_status(nip24, NIP, nip, iban, date);
}

NIP24_API WLStatus* nip24_get_whitelist_status(NIP24Client* nip24, Number type, const char* number, const char* iban, time_t date)
{
	IXMLDOMDocument2* doc = NULL;
	WLStatus* ws = NULL;

	char iban_str[MAX_STRING];
	char date_str[MAX_STRING];
	char url[MAX_STRING];

	char* code = NULL;
	char* ib = NULL;

	if (!nip24 || type < NIP || type > KRS || !number || strlen(number) == 0 || !iban || strlen(iban) == 0) {
		_nip24_set_err(nip24, NIP24_ERR_CLI_INPUT, NULL);
		goto err;
	}

	snprintf(iban_str, sizeof(iban_str), "%s", iban);

	if (!nip24_iban_is_valid(iban_str)) {
		snprintf(iban_str, sizeof(iban_str), "PL%s", iban);

		if (!nip24_iban_is_valid(iban_str)) {
			_nip24_set_err(nip24, NIP24_ERR_CLI_IBAN, NULL);
			goto err;
		}
	}

	ib = nip24_iban_normalize(iban_str);

	if (date <= 0) {
		date = time(NULL);
	}

	strftime(date_str, sizeof(date_str), "%Y-%m-%d", localtime(&date));

	// clear error
	_nip24_clear_err(nip24);

	// validate number and construct path
	snprintf(url, sizeof(url), "%s/check/whitelist/", nip24->url);

	if (!_nip24_get_path_suffix(nip24, type, number, url)) {
		goto err;
	}

	strcat_s(url, sizeof(url), "/");
	strcat_s(url, sizeof(url), ib);
	strcat_s(url, sizeof(url), "/");
	strcat_s(url, sizeof(url), date_str);

	// prepare request
	if (!_nip24_http_get(nip24, url, &doc)) {
		_nip24_set_err(nip24, NIP24_ERR_CLI_CONNECT, NULL);
		goto err;
	}

	// parse response
	code = _nip24_parse_str(doc, L"/result/error/code", NULL);

	if (code && strlen(code) > 0) {
		// error
		_nip24_set_err(nip24, atoi(code), _nip24_parse_str(doc, L"/result/error/description", NULL));
		goto err;
	}

	if (!wlstatus_new(&ws)) {
		goto err;
	}

	ws->UID = _nip24_parse_str(doc, L"/result/whitelist/uid", NULL);

	ws->NIP = _nip24_parse_str(doc, L"/result/whitelist/nip", NULL);
	ws->IBAN = _nip24_parse_str(doc, L"/result/whitelist/iban", NULL);

	ws->Valid = _nip24_parse_bool(doc, L"/result/whitelist/valid", FALSE);
	ws->Virtual = _nip24_parse_bool(doc, L"/result/whitelist/virtual", FALSE);

	ws->Status = _nip24_parse_int(doc, L"/result/whitelist/vatStatus", 0);
	ws->Result = _nip24_parse_str(doc, L"/result/whitelist/vatResult", NULL);

	ws->HashIndex = _nip24_parse_int(doc, L"/result/whitelist/hashIndex", -1);
	ws->MaskIndex = _nip24_parse_int(doc, L"/result/whitelist/maskIndex", -1);
	ws->Date = _nip24_parse_date(doc, L"/result/whitelist/date");
	ws->Source = _nip24_parse_str(doc, L"/result/whitelist/source", NULL);

err:
	if (doc) {
		doc->lpVtbl->Release(doc);
	}

	free(code);
	free(ib);

	return ws;
}

NIP24_API WLStatus* nip24_get_whitelist_status_nip(NIP24Client* nip24, const char* nip, const char* iban, time_t date)
{
	return nip24_get_whitelist_status(nip24, NIP, nip, iban, date);
}

NIP24_API SearchResult* nip24_search_vat_registry(NIP24Client* nip24, Number type, const char* number, time_t date)
{
	IXMLDOMDocument2* doc = NULL;
	SearchResult* sr = NULL;
	VATEntity* ve = NULL;

	wchar_t xpath[MAX_STRING];

	char date_str[MAX_STRING];
	char url[MAX_STRING];

	char* code = NULL;
	char* str = NULL;

	int i;
	int k;

	if (!nip24 || type < NIP || type > IBAN || !number || strlen(number) == 0) {
		_nip24_set_err(nip24, NIP24_ERR_CLI_INPUT, NULL);
		goto err;
	}

	if (date <= 0) {
		date = time(NULL);
	}

	strftime(date_str, sizeof(date_str), "%Y-%m-%d", localtime(&date));

	// clear error
	_nip24_clear_err(nip24);

	// validate number and construct path
	snprintf(url, sizeof(url), "%s/search/vat/", nip24->url);

	if (!_nip24_get_path_suffix(nip24, type, number, url)) {
		goto err;
	}

	strcat_s(url, sizeof(url), "/");
	strcat_s(url, sizeof(url), date_str);

	// prepare request
	if (!_nip24_http_get(nip24, url, &doc)) {
		_nip24_set_err(nip24, NIP24_ERR_CLI_CONNECT, NULL);
		goto err;
	}

	// parse response
	code = _nip24_parse_str(doc, L"/result/error/code", NULL);

	if (code && strlen(code) > 0) {
		// error
		_nip24_set_err(nip24, atoi(code), _nip24_parse_str(doc, L"/result/error/description", NULL));
		goto err;
	}

	if (!searchresult_new(&sr)) {
		goto err;
	}

	sr->UID = _nip24_parse_str(doc, L"/result/search/uid", NULL);
	sr->ResultsType = NIP24_RESULT_VAT_ENTITY;

	for (i = 1; ; i++) {
		_snwprintf(xpath, MAX_STRING, L"/result/search/entities/entity[%d]/nip", i);
		str = _nip24_parse_str(doc, xpath, NULL);

		if (!str || strlen(str) == 0) {
			break;
		}

		if (!vatentity_new(&ve)) {
			searchresult_free(&sr);
			goto err;
		}

		_snwprintf(xpath, MAX_STRING, L"/result/search/entities/entity[%d]/name", i);
		ve->Name = _nip24_parse_str(doc, xpath, NULL);

		ve->NIP = str;
		str = NULL;

		_snwprintf(xpath, MAX_STRING, L"/result/search/entities/entity[%d]/regon", i);
		ve->REGON = _nip24_parse_str(doc, xpath, NULL);

		_snwprintf(xpath, MAX_STRING, L"/result/search/entities/entity[%d]/krs", i);
		ve->KRS = _nip24_parse_str(doc, xpath, NULL);

		_snwprintf(xpath, MAX_STRING, L"/result/search/entities/entity[%d]/residenceAddress", i);
		ve->ResidenceAddress = _nip24_parse_str(doc, xpath, NULL);

		_snwprintf(xpath, MAX_STRING, L"/result/search/entities/entity[%d]/workingAddress", i);
		ve->WorkingAddress = _nip24_parse_str(doc, xpath, NULL);

		_snwprintf(xpath, MAX_STRING, L"/result/search/entities/entity[%d]/vat/status", i);
		ve->VATStatus = _nip24_parse_int(doc, xpath, 0);

		_snwprintf(xpath, MAX_STRING, L"/result/search/entities/entity[%d]/vat/result", i);
		ve->VATResult = _nip24_parse_str(doc, xpath, NULL);

		_snwprintf(xpath, MAX_STRING, L"/result/search/entities/entity[%d]/representatives", i);
		_nip24_parse_vatperson(doc, xpath, &ve->Representatives, &ve->RepresentativesCount);

		_snwprintf(xpath, MAX_STRING, L"/result/search/entities/entity[%d]/authorizedClerks", i);
		_nip24_parse_vatperson(doc, xpath, &ve->AuthorizedClerks, &ve->AuthorizedClerksCount);

		_snwprintf(xpath, MAX_STRING, L"/result/search/entities/entity[%d]/partners", i);
		_nip24_parse_vatperson(doc, xpath, &ve->Partners, &ve->PartnersCount);

		for (k = 1; ; k++) {
			_snwprintf(xpath, MAX_STRING, L"/result/search/entities/entity[%d]/ibans/iban[%d]", i, k);
			str = _nip24_parse_str(doc, xpath, NULL);

			if (!str || strlen(str) == 0) {
				break;
			}

			// add
			ve->IBANsCount++;

			if ((ve->IBANs = (char**)realloc(ve->IBANs, sizeof(char*) * ve->IBANsCount)) == NULL) {
				searchresult_free(&sr);
				goto err;
			}

			ve->IBANs[ve->IBANsCount - 1] = str;
			str = NULL;
		}

		_snwprintf(xpath, MAX_STRING, L"/result/search/entities/entity[%d]/hasVirtualAccounts", i);
		str = _nip24_parse_str(doc, xpath, "false");
		ve->HasVirtualAccounts = (strcmp(str, "true") == 0 ? TRUE : FALSE);

		free(str);
		str = NULL;

		_snwprintf(xpath, MAX_STRING, L"/result/search/entities/entity[%d]/registrationLegalDate", i);
		ve->RegistrationLegalDate = _nip24_parse_date(doc, xpath);

		_snwprintf(xpath, MAX_STRING, L"/result/search/entities/entity[%d]/registrationDenialDate", i);
		ve->RegistrationDenialDate = _nip24_parse_date(doc, xpath);

		_snwprintf(xpath, MAX_STRING, L"/result/search/entities/entity[%d]/registrationDenialBasis", i);
		ve->RegistrationDenialBasis = _nip24_parse_str(doc, xpath, NULL);

		_snwprintf(xpath, MAX_STRING, L"/result/search/entities/entity[%d]/restorationDate", i);
		ve->RestorationDate = _nip24_parse_date(doc, xpath);

		_snwprintf(xpath, MAX_STRING, L"/result/search/entities/entity[%d]/restorationBasis", i);
		ve->RestorationBasis = _nip24_parse_str(doc, xpath, NULL);

		_snwprintf(xpath, MAX_STRING, L"/result/search/entities/entity[%d]/removalDate", i);
		ve->RemovalDate = _nip24_parse_date(doc, xpath);

		_snwprintf(xpath, MAX_STRING, L"/result/search/entities/entity[%d]/removalBasis", i);
		ve->RemovalBasis = _nip24_parse_str(doc, xpath, NULL);

		// add
		sr->ResultsCount++;

		if ((sr->Results.VATEntity = (VATEntity**)realloc(sr->Results.VATEntity, sizeof(VATEntity*) * sr->ResultsCount)) == NULL) {
			searchresult_free(&sr);
			goto err;
		}

		sr->Results.VATEntity[sr->ResultsCount - 1] = ve;
		ve = NULL;
	}

	sr->ID = _nip24_parse_str(doc, L"/result/search/id", NULL);
	sr->Date = _nip24_parse_date(doc, L"/result/search/date");
	sr->Source = _nip24_parse_str(doc, L"/result/search/source", NULL);

err:
	if (doc) {
		doc->lpVtbl->Release(doc);
	}

	vatentity_free(&ve);

	free(code);
	free(str);

	return sr;
}

NIP24_API SearchResult* nip24_search_vat_registry_nip(NIP24Client* nip24, const char* nip, time_t date)
{
	return nip24_search_vat_registry(nip24, NIP, nip, date);
}

NIP24_API AccountStatus* nip24_get_account_status(NIP24Client* nip24)
{
	IXMLDOMDocument2* doc = NULL;
	AccountStatus* status = NULL;

	char url[MAX_STRING];

	char* code = NULL;

	if (!nip24) {
		_nip24_set_err(nip24, NIP24_ERR_CLI_INPUT, NULL);
		goto err;
	}

	// clear error
	_nip24_clear_err(nip24);

	// validate number and construct path
	snprintf(url, sizeof(url), "%s/check/account/status", nip24->url);

	// prepare request
	if (!_nip24_http_get(nip24, url, &doc)) {
		_nip24_set_err(nip24, NIP24_ERR_CLI_CONNECT, NULL);
		goto err;
	}

	// parse response
	code = _nip24_parse_str(doc, L"/result/error/code", NULL);

	if (code && strlen(code) > 0) {
		// error
		_nip24_set_err(nip24, atoi(code), _nip24_parse_str(doc, L"/result/error/description", NULL));
		goto err;
	}

	if (!accountstatus_new(&status)) {
		goto err;
	}

	status->UID = _nip24_parse_str(doc, L"/result/account/uid", NULL);
	status->Type = _nip24_parse_str(doc, L"/result/account/type", NULL);
	status->ValidTo = _nip24_parse_datetime(doc, L"/result/account/validTo");
	status->BillingPlanName = _nip24_parse_str(doc, L"/result/account/billingPlan/name", NULL);

	status->SubscriptionPrice = _nip24_parse_double(doc, L"/result/account/billingPlan/subscriptionPrice", 0);
	status->ItemPrice = _nip24_parse_double(doc, L"/result/account/billingPlan/itemPrice", 0);
	status->ItemPriceStatus = _nip24_parse_double(doc, L"/result/account/billingPlan/itemPriceCheckStatus", 0);
	status->ItemPriceInvoice = _nip24_parse_double(doc, L"/result/account/billingPlan/itemPriceInvoiceData", 0);
	status->ItemPriceAll = _nip24_parse_double(doc, L"/result/account/billingPlan/itemPriceAllData", 0);
	status->ItemPriceIBAN = _nip24_parse_double(doc, L"/result/account/billingPlan/itemPriceAllIBAN", 0);
	status->ItemPriceWhitelist = _nip24_parse_double(doc, L"/result/account/billingPlan/itemPriceWLStatus", 0);
	status->ItemPriceSearchVAT = _nip24_parse_double(doc, L"/result/account/billingPlan/itemPriceSearchVAT", 0);

	status->Limit = _nip24_parse_int(doc, L"/result/account/billingPlan/limit", 0);
	status->RequestDelay = _nip24_parse_int(doc, L"/result/account/billingPlan/requestDelay", 0);
	status->DomainLimit = _nip24_parse_int(doc, L"/result/account/billingPlan/domainLimit", 0);

	status->OverPlanAllowed = _nip24_parse_bool(doc, L"/result/account/billingPlan/overplanAllowed", FALSE);
	status->TerytCodes = _nip24_parse_bool(doc, L"/result/account/billingPlan/terytCodes", FALSE);
	status->ExcelAddIn = _nip24_parse_bool(doc, L"/result/account/billingPlan/excelAddin", FALSE);
	status->JPKVAT = _nip24_parse_bool(doc, L"/result/account/billingPlan/jpkVat", FALSE);
	status->CLI = _nip24_parse_bool(doc, L"/result/account/billingPlan/cli", FALSE);
	status->Stats = _nip24_parse_bool(doc, L"/result/account/billingPlan/stats", FALSE);
	status->NIPMonitor = _nip24_parse_bool(doc, L"/result/account/billingPlan/nipMonitor", FALSE);

	status->SearchByNIP = _nip24_parse_bool(doc, L"/result/account/billingPlan/searchByNip", FALSE);
	status->SearchByREGON = _nip24_parse_bool(doc, L"/result/account/billingPlan/searchByRegon", FALSE);
	status->SearchByKRS = _nip24_parse_bool(doc, L"/result/account/billingPlan/searchByKrs", FALSE);

	status->FuncIsActive = _nip24_parse_bool(doc, L"/result/account/billingPlan/funcIsActive", FALSE);
	status->FuncGetInvoiceData = _nip24_parse_bool(doc, L"/result/account/billingPlan/funcGetInvoiceData", FALSE);
	status->FuncGetAllData = _nip24_parse_bool(doc, L"/result/account/billingPlan/funcGetAllData", FALSE);
	status->FuncGetVIESData = _nip24_parse_bool(doc, L"/result/account/billingPlan/funcGetVIESData", FALSE);
	status->FuncGetVATStatus = _nip24_parse_bool(doc, L"/result/account/billingPlan/funcGetVATStatus", FALSE);
	status->FuncGetIBANStatus = _nip24_parse_bool(doc, L"/result/account/billingPlan/funcGetIBANStatus", FALSE);
	status->FuncGetWhitelistStatus = _nip24_parse_bool(doc, L"/result/account/billingPlan/funcGetWLStatus", FALSE);
	status->FuncSearchVAT = _nip24_parse_bool(doc, L"/result/account/billingPlan/funcSearchVAT", FALSE);

	status->InvoiceDataCount = _nip24_parse_int(doc, L"/result/account/requests/invoiceData", 0);
	status->AllDataCount = _nip24_parse_int(doc, L"/result/account/requests/allData", 0);
	status->FirmStatusCount = _nip24_parse_int(doc, L"/result/account/requests/firmStatus", 0);
	status->VATStatusCount = _nip24_parse_int(doc, L"/result/account/requests/vatStatus", 0);
	status->VIESStatusCount = _nip24_parse_int(doc, L"/result/account/requests/viesStatus", 0);
	status->IBANStatusCount = _nip24_parse_int(doc, L"/result/account/requests/ibanStatus", 0);
	status->WhitelistStatusCount = _nip24_parse_int(doc, L"/result/account/requests/wlStatus", 0);
	status->SearchVATCount = _nip24_parse_int(doc, L"/result/account/requests/searchVAT", 0);
	status->TotalCount = _nip24_parse_int(doc, L"/result/account/requests/total", 0);

err:
	if (doc) {
		doc->lpVtbl->Release(doc);
	}

	free(code);

	return status;
}
