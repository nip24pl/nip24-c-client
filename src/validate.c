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


#define CHAR2NUM(c)		((c) - 48)

static BOOL _nip24_regon_is_valid_R9(const char* regon)
{
	int w[] = {
		8, 9, 2, 3, 4, 5, 6, 7
	};

	int wlen = 8;
	int sum = 0;
	int i;

	for (i = 0; i < wlen; i++) {
		sum += CHAR2NUM(regon[i]) * w[i];
	}

	sum %= 11;

	if (sum == 10) {
		sum = 0;
	}

	if (sum != CHAR2NUM(regon[8])) {
		return FALSE;
	}

	return TRUE;
}

static BOOL _nip24_regon_is_valid_R14(const char* regon)
{
	int w[] = {
		2, 4, 8, 5, 0, 9, 7, 3, 6, 1, 2, 4, 8
	};

	int wlen = 13;
	int sum = 0;
	int i;

	for (i = 0; i < wlen; i++) {
		sum += CHAR2NUM(regon[i]) * w[i];
	}

	sum %= 11;

	if (sum == 10) {
		sum = 0;
	}

	if (sum != CHAR2NUM(regon[13])) {
		return FALSE;
	}

	return TRUE;
}

static BOOL _nip24_isdigit(char* str, int start, int count)
{
	int i;

	for (i = start; i < (start + count); i++) {
		if (!isdigit(str[i])) {
			return FALSE;
		}
	}

	return TRUE;
}

static BOOL _nip24_isalpha(char* str, int start, int count)
{
	int i;

	for (i = start; i < (start + count); i++) {
		if (!isalpha(str[i])) {
			return FALSE;
		}
	}

	return TRUE;
}

static BOOL _nip24_isalnum(char* str, int start, int count)
{
	int i;

	for (i = start; i < (start + count); i++) {
		if (!isalnum(str[i])) {
			return FALSE;
		}
	}

	return TRUE;
}

static BOOL _nip24_isalnum_ext(char* str, int start, int count)
{
	int i;

	for (i = start; i < (start + count); i++) {
		if (!isalnum(str[i]) && str[i] != '+' && str[i] != '*') {
			return FALSE;
		}
	}

	return TRUE;
}

/////////////////////////////////////////////////////////////////

NIP24_API char* nip24_nip_normalize(const char* nip)
{
	char num[MAX_NUMBER];

	int len;
	int p;
	int i;

	if (!nip || (len = (int)strlen(nip)) < 10 || len > 13) {
		return NULL;
	}

	// [0-9]{10}
	memset(num, 0, sizeof(num));

	for (i = 0, p = 0; i < len; i++) {
		if (isdigit(nip[i])) {
			num[p++] = nip[i];
		}
	}

	if (strlen(num) != 10) {
		return NULL;
	}

	return strdup(num);
}

NIP24_API BOOL nip24_nip_is_valid(const char* nip)
{
	char* num = nip24_nip_normalize(nip);

	int w[] = {
		6, 5, 7, 2, 3, 4, 5, 6, 7
	};

	int wlen = 9;
	int sum = 0;
	int i;

	if (!num) {
		return FALSE;
	}

	for (i = 0; i < wlen; i++) {
		sum += CHAR2NUM(num[i]) * w[i];
	}

	sum %= 11;

	if (sum != CHAR2NUM(num[9])) {
		free(num);
		return FALSE;
	}

	free(num);

	return TRUE;
}

NIP24_API char* nip24_regon_normalize(const char* regon)
{
	char num[MAX_NUMBER];

	int len;
	int p;
	int i;

	if (!regon || (len = (int)strlen(regon)) < 9 || len > 14) {
		return NULL;
	}

	// [0-9]{9,14}
	memset(num, 0, sizeof(num));

	for (i = 0, p = 0; i < len; i++) {
		if (isdigit(regon[i])) {
			num[p++] = regon[i];
		}
	}

	if (strlen(num) != 9 && strlen(num) != 14) {
		return NULL;
	}

	return strdup(num);
}

NIP24_API BOOL nip24_regon_is_valid(const char* regon)
{
	BOOL ret;

	char* num = nip24_regon_normalize(regon);

	if (!num) {
		return FALSE;
	}

	if (strlen(num) == 9) {
		ret = _nip24_regon_is_valid_R9(num);
		free(num);

		return ret;
	}
	else {
		ret = _nip24_regon_is_valid_R9(num);

		if (!ret) {
			free(num);
			return FALSE;
		}

		ret = _nip24_regon_is_valid_R14(num);
		free(num);

		return ret;
	}
}

NIP24_API char* nip24_krs_normalize(const char* krs)
{
	char num[MAX_NUMBER];

	int len;

	if (!krs || (len = (int)strlen(krs)) <= 0) {
		return NULL;
	}

	// [0-9]{10}
	snprintf(num, sizeof(num), "%010" PRIu64, atoll(krs));

	if (strlen(num) != 10) {
		return NULL;
	}

	return strdup(num);
}

NIP24_API BOOL nip24_krs_is_valid(const char* krs)
{
	char* num = nip24_krs_normalize(krs);

	if (!num) {
		return FALSE;
	}

	free(num);

	return TRUE;
}

NIP24_API char* nip24_euvat_normalize(const char* euvat)
{
	char num[MAX_NUMBER];

	int len;
	int p;
	int i;

	if (!euvat || (len = (int)strlen(euvat)) == 0) {
		return NULL;
	}

	memset(num, 0, sizeof(num));

	for (i = 0, p = 0; i < len; i++) {
		if ((isalnum(euvat[i]) || euvat[i] == '+' || euvat[i] == '*') && p < (sizeof(num) - 1)) {
			num[p++] = toupper(euvat[i]);
		}
	}

	if ((len = (int)strlen(num)) < 4 || len > 14) {
		return NULL;
	}

	return strdup(num);
}

NIP24_API BOOL nip24_euvat_is_valid(const char* euvat)
{
	BOOL ret = FALSE;

	char* num = nip24_euvat_normalize(euvat);

	int len;

	if (!num) {
		goto err;
	}

	len = (int)strlen(num);

	if (strncmp(num, "AT", 2) == 0) {
		// ATU\\d{8}
		if (len != (3 + 8) || num[2] != 'U') {
			goto err;
		}

		if (!_nip24_isdigit(num, 3, 8)) {
			goto err;
		}
	}
	else if (strncmp(num, "BE", 2) == 0) {
		// BE[0-1]{1}\d{9}
		if (len != (3 + 9) || (num[2] != '0' && num[2] != '1')) {
			goto err;
		}

		if (!_nip24_isdigit(num, 3, 9)) {
			goto err;
		}
	}
	else if (strncmp(num, "BG", 2) == 0) {
		// BG\\d{9,10}
		if (len < (2 + 9) || len > (2 + 10)) {
			goto err;
		}

		if (!_nip24_isdigit(num, 2, len - 2)) {
			goto err;
		}
	}
	else if (strncmp(num, "CY", 2) == 0) {
		// CY\d{8}[A-Z]{1}
		if (len != (2 + 8 + 1) || !isalpha(num[len - 1])) {
			goto err;
		}

		if (!_nip24_isdigit(num, 2, 8)) {
			goto err;
		}
	}
	else if (strncmp(num, "CZ", 2) == 0) {
		// CZ\\d{8,10}
		if (len < (2 + 8) || len > (2 + 10)) {
			goto err;
		}

		if (!_nip24_isdigit(num, 2, len - 2)) {
			goto err;
		}
	}
	else if (strncmp(num, "DE", 2) == 0) {
		// DE\\d{9}
		if (len != (2 + 9)) {
			goto err;
		}

		if (!_nip24_isdigit(num, 2, 9)) {
			goto err;
		}
	}
	else if (strncmp(num, "DK", 2) == 0) {
		// DK\\d{8}
		if (len != (2 + 8)) {
			goto err;
		}

		if (!_nip24_isdigit(num, 2, 8)) {
			goto err;
		}
	}
	else if (strncmp(num, "EE", 2) == 0) {
		// EE\\d{9}
		if (len != (2 + 9)) {
			goto err;
		}

		if (!_nip24_isdigit(num, 2, 9)) {
			goto err;
		}
	}
	else if (strncmp(num, "EL", 2) == 0) {
		// EL\\d{9}
		if (len != (2 + 9)) {
			goto err;
		}

		if (!_nip24_isdigit(num, 2, 9)) {
			goto err;
		}
	}
	else if (strncmp(num, "ES", 2) == 0) {
		// ES[A-Z0-9]{1}\d{7}[A-Z0-9]{1}
		if (len != (2 + 1 + 7 + 1)) {
			goto err;
		}

		if (!_nip24_isalnum(num, 2, 1)) {
			goto err;
		}

		if (!_nip24_isdigit(num, 3, 7)) {
			goto err;
		}

		if (!_nip24_isalnum(num, 10, 1)) {
			goto err;
		}
	}
	else if (strncmp(num, "FI", 2) == 0) {
		// FI\\d{8}
		if (len != (2 + 8)) {
			goto err;
		}

		if (!_nip24_isdigit(num, 2, 8)) {
			goto err;
		}
	}
	else if (strncmp(num, "FR", 2) == 0) {
		// FR[A-Z0-9]{2}\\d{9}
		if (len != (2 + 2 + 9)) {
			goto err;
		}

		if (!_nip24_isalnum(num, 2, 2)) {
			goto err;
		}

		if (!_nip24_isdigit(num, 4, 9)) {
			goto err;
		}
	}
	else if (strncmp(num, "HR", 2) == 0) {
		// HR\\d{11}
		if (len != (2 + 11)) {
			goto err;
		}

		if (!_nip24_isdigit(num, 2, 11)) {
			goto err;
		}
	}
	else if (strncmp(num, "HU", 2) == 0) {
		// HU\\d{8}
		if (len != (2 + 8)) {
			goto err;
		}

		if (!_nip24_isdigit(num, 2, 8)) {
			goto err;
		}
	}
	else if (strncmp(num, "IE", 2) == 0) {
		// IE[A-Z0-9+*]{8,9}
		if (len < (2 + 8) || len > (2 + 9)) {
			goto err;
		}

		if (!_nip24_isalnum_ext(num, 2, len - 2)) {
			goto err;
		}
	}
	else if (strncmp(num, "IT", 2) == 0) {
		// IT\\d{11}
		if (len != (2 + 11)) {
			goto err;
		}

		if (!_nip24_isdigit(num, 2, 11)) {
			goto err;
		}
	}
	else if (strncmp(num, "LT", 2) == 0) {
		// LT\\d{9,12}
		if (len < (2 + 9) || len > (2 + 12)) {
			goto err;
		}

		if (!_nip24_isdigit(num, 2, len - 2)) {
			goto err;
		}
	}
	else if (strncmp(num, "LU", 2) == 0) {
		// LU\\d{8}
		if (len != (2 + 8)) {
			goto err;
		}

		if (!_nip24_isdigit(num, 2, 8)) {
			goto err;
		}
	}
	else if (strncmp(num, "LV", 2) == 0) {
		// LV\\d{11}
		if (len != (2 + 11)) {
			goto err;
		}

		if (!_nip24_isdigit(num, 2, 11)) {
			goto err;
		}
	}
	else if (strncmp(num, "MT", 2) == 0) {
		// MT\\d{8}
		if (len != (2 + 8)) {
			goto err;
		}

		if (!_nip24_isdigit(num, 2, 8)) {
			goto err;
		}
	}
	else if (strncmp(num, "NL", 2) == 0) {
		// NL[A-Z0-9+*]{12}
		if (len != (2 + 12)) {
			goto err;
		}

		if (!_nip24_isalnum_ext(num, 2, 12)) {
			goto err;
		}
	}
	else if (strncmp(num, "PL", 2) == 0) {
		// PL\\d{10}
		if (len != (2 + 10)) {
			goto err;
		}

		if (!_nip24_isdigit(num, 2, 10)) {
			goto err;
		}
	}
	else if (strncmp(num, "PT", 2) == 0) {
		// PT\\d{9}
		if (len != (2 + 9)) {
			goto err;
		}

		if (!_nip24_isdigit(num, 2, 9)) {
			goto err;
		}
	}
	else if (strncmp(num, "RO", 2) == 0) {
		// RO\\d{2,10}
		if (len < (2 + 2) || len > (2 + 10)) {
			goto err;
		}

		if (!_nip24_isdigit(num, 2, len - 2)) {
			goto err;
		}
	}
	else if (strncmp(num, "SE", 2) == 0) {
		// SE\\d{12}
		if (len != (2 + 12)) {
			goto err;
		}

		if (!_nip24_isdigit(num, 2, 12)) {
			goto err;
		}
	}
	else if (strncmp(num, "SI", 2) == 0) {
		// SI\\d{8}
		if (len != (2 + 8)) {
			goto err;
		}

		if (!_nip24_isdigit(num, 2, 8)) {
			goto err;
		}
	}
	else if (strncmp(num, "SK", 2) == 0) {
		// SK\\d{10}
		if (len != (2 + 10)) {
			goto err;
		}

		if (!_nip24_isdigit(num, 2, 10)) {
			goto err;
		}
	}
	else if (strncmp(num, "XI", 2) == 0) {
		// XI[A-Z0-9]{5,12}
		if (len < (2 + 5) || len > (2 + 12)) {
			goto err;
		}

		if (!_nip24_isalnum(num, 2, len - 2)) {
			goto err;
		}
	}
	else {
		goto err;
	}

	if (strncmp(num, "PL", 2) == 0 && !nip24_nip_is_valid(num + 2)) {
		goto err;
	}

	ret = TRUE;

err:
	free(num);

	return ret;
}

NIP24_API char* nip24_iban_normalize(const char* iban)
{
	char num[MAX_NUMBER];

	int len;
	int p;
	int i;

	if (!iban || (len = (int)strlen(iban)) == 0) {
		return NULL;
	}

	memset(num, 0, sizeof(num));

	for (i = 0, p = 0; i < len; i++) {
		if (isalnum(iban[i]) && p < (sizeof(num) - 1)) {
			num[p++] = toupper(iban[i]);
		}
	}

	if ((len = (int)strlen(num)) < 15 || len > 32) {
		return NULL;
	}

	return strdup(num);
}

NIP24_API BOOL nip24_iban_is_valid(const char* iban)
{
	BOOL ret = FALSE;

	char* num = nip24_iban_normalize(iban);

	char str[MAX_NUMBER * 2];
	char sb[MAX_NUMBER];

	int chk;
	int len;
	int i;
	int p;

	if (!num) {
		goto err;
	}

	len = (int)strlen(num);

	if (strncmp(num, "AD", 2) == 0) {
		// AD\\d{10}[A-Z0-9]{12}
		if (len != (2 + 10 + 12)) {
			goto err;
		}

		if (!_nip24_isdigit(num, 2, 10) || !_nip24_isalnum(num, 12, 12)) {
			goto err;
		}
	}
	else if (strncmp(num, "AE", 2) == 0) {
		// AE\\d{21}
		if (len != (2 + 21)) {
			goto err;
		}

		if (!_nip24_isdigit(num, 2, 21)) {
			goto err;
		}
	}
	else if (strncmp(num, "AL", 2) == 0) {
		// AL\\d{10}[A-Z0-9]{16}
		if (len != (2 + 10 + 16)) {
			goto err;
		}

		if (!_nip24_isdigit(num, 2, 10) || !_nip24_isalnum(num, 12, 16)) {
			goto err;
		}
	}
	else if (strncmp(num, "AT", 2) == 0) {
		// AT\\d{18}
		if (len != (2 + 18)) {
			goto err;
		}

		if (!_nip24_isdigit(num, 2, 18)) {
			goto err;
		}
	}
	else if (strncmp(num, "AZ", 2) == 0) {
		// AZ\\d{2}[A-Z]{4}[A-Z0-9]{20}
		if (len != (2 + 2 + 4 + 20)) {
			goto err;
		}

		if (!_nip24_isdigit(num, 2, 2) || !_nip24_isalpha(num, 4, 4) || !_nip24_isalnum(num, 8, 20)) {
			goto err;
		}
	}
	else if (strncmp(num, "BA", 2) == 0) {
		// BA\\d{18}
		if (len != (2 + 18)) {
			goto err;
		}

		if (!_nip24_isdigit(num, 2, 18)) {
			goto err;
		}
	}
	else if (strncmp(num, "BE", 2) == 0) {
		// BE\\d{14}
		if (len != (2 + 14)) {
			goto err;
		}

		if (!_nip24_isdigit(num, 2, 14)) {
			goto err;
		}
	}
	else if (strncmp(num, "BG", 2) == 0) {
		// BG\\d{2}[A-Z]{4}\\d{6}[A-Z0-9]{8}
		if (len != (2 + 2 + 4 + 6 + 8)) {
			goto err;
		}

		if (!_nip24_isdigit(num, 2, 2) || !_nip24_isalpha(num, 4, 4) || !_nip24_isdigit(num, 8, 6) || !_nip24_isalnum(num, 14, 8)) {
			goto err;
		}
	}
	else if (strncmp(num, "BH", 2) == 0) {
		// BH\\d{2}[A-Z]{4}[A-Z0-9]{14}
		if (len != (2 + 2 + 4 + 14)) {
			goto err;
		}

		if (!_nip24_isdigit(num, 2, 2) || !_nip24_isalpha(num, 4, 4) || !_nip24_isalnum(num, 8, 14)) {
			goto err;
		}
	}
	else if (strncmp(num, "BR", 2) == 0) {
		// BR\\d{25}[A-Z]{1}[A-Z0-9]{1}
		if (len != (2 + 25 + 1 + 1)) {
			goto err;
		}

		if (!_nip24_isdigit(num, 2, 25) || !_nip24_isalpha(num, 27, 1) || !_nip24_isalnum(num, 28, 1)) {
			goto err;
		}
	}
	else if (strncmp(num, "BY", 2) == 0) {
		// BY\\d{2}[A-Z0-9]{4}\\d{4}[A-Z0-9]{16}
		if (len != (2 + 2 + 4 + 4 + 16)) {
			goto err;
		}

		if (!_nip24_isdigit(num, 2, 2) || !_nip24_isalnum(num, 4, 4) || !_nip24_isdigit(num, 8, 4) || !_nip24_isalnum(num, 12, 16)) {
			goto err;
		}
	}
	else if (strncmp(num, "CH", 2) == 0) {
		// CH\\d{7}[A-Z0-9]{12}
		if (len != (2 + 7 + 12)) {
			goto err;
		}

		if (!_nip24_isdigit(num, 2, 7) || !_nip24_isalnum(num, 9, 12)) {
			goto err;
		}
	}
	else if (strncmp(num, "CR", 2) == 0) {
		// CR\\d{20}
		if (len != (2 + 20)) {
			goto err;
		}

		if (!_nip24_isdigit(num, 2, 20)) {
			goto err;
		}
	}
	else if (strncmp(num, "CY", 2) == 0) {
		// CY\\d{10}[A-Z0-9]{16}
		if (len != (2 + 10 + 16)) {
			goto err;
		}

		if (!_nip24_isdigit(num, 2, 10) || !_nip24_isalnum(num, 12, 16)) {
			goto err;
		}
	}
	else if (strncmp(num, "CZ", 2) == 0) {
		// CZ\\d{22}
		if (len != (2 + 22)) {
			goto err;
		}

		if (!_nip24_isdigit(num, 2, 22)) {
			goto err;
		}
	}
	else if (strncmp(num, "DE", 2) == 0) {
		// DE\\d{20}
		if (len != (2 + 20)) {
			goto err;
		}

		if (!_nip24_isdigit(num, 2, 20)) {
			goto err;
		}
	}
	else if (strncmp(num, "DK", 2) == 0) {
		// DK\\d{16}
		if (len != (2 + 16)) {
			goto err;
		}

		if (!_nip24_isdigit(num, 2, 16)) {
			goto err;
		}
	}
	else if (strncmp(num, "DO", 2) == 0) {
		// DO\\d{2}[A-Z0-9]{4}\\d{20}
		if (len != (2 + 2 + 4 + 20)) {
			goto err;
		}

		if (!_nip24_isdigit(num, 2, 2) || !_nip24_isalnum(num, 4, 4) || !_nip24_isdigit(num, 8, 20)) {
			goto err;
		}
	}
	else if (strncmp(num, "EE", 2) == 0) {
		// EE\\d{18}
		if (len != (2 + 18)) {
			goto err;
		}

		if (!_nip24_isdigit(num, 2, 18)) {
			goto err;
		}
	}
	else if (strncmp(num, "ES", 2) == 0) {
		// ES\\d{22}
		if (len != (2 + 22)) {
			goto err;
		}

		if (!_nip24_isdigit(num, 2, 22)) {
			goto err;
		}
	}
	else if (strncmp(num, "FI", 2) == 0) {
		// FI\\d{16}
		if (len != (2 + 16)) {
			goto err;
		}

		if (!_nip24_isdigit(num, 2, 16)) {
			goto err;
		}
	}
	else if (strncmp(num, "FO", 2) == 0) {
		// FO\\d{16}
		if (len != (2 + 16)) {
			goto err;
		}

		if (!_nip24_isdigit(num, 2, 16)) {
			goto err;
		}
	}
	else if (strncmp(num, "FR", 2) == 0) {
		// FR\\d{12}[A-Z0-9]{11}\\d{2}
		if (len != (2 + 12 + 11 + 2)) {
			goto err;
		}

		if (!_nip24_isdigit(num, 2, 12) || !_nip24_isalnum(num, 14, 11) || !_nip24_isdigit(num, 25, 2)) {
			goto err;
		}
	}
	else if (strncmp(num, "GB", 2) == 0) {
		// GB\\d{2}[A-Z]{4}\\d{14}
		if (len != (2 + 2 + 4 + 14)) {
			goto err;
		}

		if (!_nip24_isdigit(num, 2, 2) || !_nip24_isalpha(num, 4, 4) || !_nip24_isdigit(num, 8, 14)) {
			goto err;
		}
	}
	else if (strncmp(num, "GE", 2) == 0) {
		// GE\\d{2}[A-Z]{2}\\d{16}
		if (len != (2 + 2 + 2 + 16)) {
			goto err;
		}

		if (!_nip24_isdigit(num, 2, 2) || !_nip24_isalpha(num, 4, 2) || !_nip24_isdigit(num, 6, 16)) {
			goto err;
		}
	}
	else if (strncmp(num, "GI", 2) == 0) {
		// GI\\d{2}[A-Z]{4}[A-Z0-9]{15}
		if (len != (2 + 2 + 4 + 15)) {
			goto err;
		}

		if (!_nip24_isdigit(num, 2, 2) || !_nip24_isalpha(num, 4, 4) || !_nip24_isalnum(num, 8, 15)) {
			goto err;
		}
	}
	else if (strncmp(num, "GL", 2) == 0) {
		// GL\\d{16}
		if (len != (2 + 16)) {
			goto err;
		}

		if (!_nip24_isdigit(num, 2, 16)) {
			goto err;
		}
	}
	else if (strncmp(num, "GR", 2) == 0) {
		// GR\\d{9}[A-Z0-9]{16}
		if (len != (2 + 9 + 16)) {
			goto err;
		}

		if (!_nip24_isdigit(num, 2, 9) || !_nip24_isalnum(num, 11, 16)) {
			goto err;
		}
	}
	else if (strncmp(num, "GT", 2) == 0) {
		// GT\\d{2}[A-Z0-9]{24}
		if (len != (2 + 2 + 24)) {
			goto err;
		}

		if (!_nip24_isdigit(num, 2, 2) || !_nip24_isalnum(num, 4, 24)) {
			goto err;
		}
	}
	else if (strncmp(num, "HR", 2) == 0) {
		// HR\\d{19}
		if (len != (2 + 19)) {
			goto err;
		}

		if (!_nip24_isdigit(num, 2, 19)) {
			goto err;
		}
	}
	else if (strncmp(num, "HU", 2) == 0) {
		// HU\\d{26}
		if (len != (2 + 26)) {
			goto err;
		}

		if (!_nip24_isdigit(num, 2, 26)) {
			goto err;
		}
	}
	else if (strncmp(num, "IE", 2) == 0) {
		// IE\\d{2}[A-Z]{4}\\d{14}
		if (len != (2 + 2 + 4 + 14)) {
			goto err;
		}

		if (!_nip24_isdigit(num, 2, 2) || !_nip24_isalpha(num, 4, 4) || !_nip24_isdigit(num, 8, 14)) {
			goto err;
		}
	}
	else if (strncmp(num, "IL", 2) == 0) {
		// IL\\d{21}
		if (len != (2 + 21)) {
			goto err;
		}

		if (!_nip24_isdigit(num, 2, 21)) {
			goto err;
		}
	}
	else if (strncmp(num, "IQ", 2) == 0) {
		// IQ\\d{2}[A-Z]{4}\\d{15}
		if (len != (2 + 2 + 4 + 15)) {
			goto err;
		}

		if (!_nip24_isdigit(num, 2, 2) || !_nip24_isalpha(num, 4, 4) || !_nip24_isdigit(num, 8, 15)) {
			goto err;
		}
	}
	else if (strncmp(num, "IS", 2) == 0) {
		// IS\\d{24}
		if (len != (2 + 24)) {
			goto err;
		}

		if (!_nip24_isdigit(num, 2, 24)) {
			goto err;
		}
	}
	else if (strncmp(num, "IT", 2) == 0) {
		// IT\\d{2}[A-Z]{1}\\d{10}[A-Z0-9]{12}
		if (len != (2 + 2 + 1 + 10 + 12)) {
			goto err;
		}

		if (!_nip24_isdigit(num, 2, 2) || !_nip24_isalpha(num, 4, 1) || !_nip24_isdigit(num, 5, 10) || !_nip24_isalnum(num, 15, 12)) {
			goto err;
		}
	}
	else if (strncmp(num, "JO", 2) == 0) {
		// JO\\d{2}[A-Z]{4}\\d{4}[A-Z0-9]{18}
		if (len != (2 + 2 + 4 + 4 + 18)) {
			goto err;
		}

		if (!_nip24_isdigit(num, 2, 2) || !_nip24_isalpha(num, 4, 4) || !_nip24_isdigit(num, 8, 4) || !_nip24_isalnum(num, 12, 18)) {
			goto err;
		}
	}
	else if (strncmp(num, "KW", 2) == 0) {
		// KW\\d{2}[A-Z]{4}[A-Z0-9]{22}
		if (len != (2 + 2 + 4 + 22)) {
			goto err;
		}

		if (!_nip24_isdigit(num, 2, 2) || !_nip24_isalpha(num, 4, 4) || !_nip24_isalnum(num, 8, 22)) {
			goto err;
		}
	}
	else if (strncmp(num, "KZ", 2) == 0) {
		// KZ\\d{5}[A-Z0-9]{13}
		if (len != (2 + 5 + 13)) {
			goto err;
		}

		if (!_nip24_isdigit(num, 2, 5) || !_nip24_isalnum(num, 7, 13)) {
			goto err;
		}
	}
	else if (strncmp(num, "LB", 2) == 0) {
		// LB\\d{6}[A-Z0-9]{20}
		if (len != (2 + 6 + 20)) {
			goto err;
		}

		if (!_nip24_isdigit(num, 2, 6) || !_nip24_isalnum(num, 8, 20)) {
			goto err;
		}
	}
	else if (strncmp(num, "LC", 2) == 0) {
		// LC\\d{2}[A-Z]{4}[A-Z0-9]{24}
		if (len != (2 + 2 + 4 + 24)) {
			goto err;
		}

		if (!_nip24_isdigit(num, 2, 2) || !_nip24_isalpha(num, 4, 4) || !_nip24_isalnum(num, 8, 24)) {
			goto err;
		}
	}
	else if (strncmp(num, "LI", 2) == 0) {
		// LI\\d{7}[A-Z0-9]{12}
		if (len != (2 + 7 + 12)) {
			goto err;
		}

		if (!_nip24_isdigit(num, 2, 7) || !_nip24_isalnum(num, 9, 12)) {
			goto err;
		}
	}
	else if (strncmp(num, "LT", 2) == 0) {
		// LT\\d{18}
		if (len != (2 + 18)) {
			goto err;
		}

		if (!_nip24_isdigit(num, 2, 18)) {
			goto err;
		}
	}
	else if (strncmp(num, "LU", 2) == 0) {
		// LU\\d{5}[A-Z0-9]{13}
		if (len != (2 + 5 + 13)) {
			goto err;
		}

		if (!_nip24_isdigit(num, 2, 5) || !_nip24_isalnum(num, 7, 13)) {
			goto err;
		}
	}
	else if (strncmp(num, "LV", 2) == 0) {
		// LV\\d{2}[A-Z]{4}[A-Z0-9]{13}
		if (len != (2 + 2 + 4 + 13)) {
			goto err;
		}

		if (!_nip24_isdigit(num, 2, 2) || !_nip24_isalpha(num, 4, 4) || !_nip24_isalnum(num, 8, 13)) {
			goto err;
		}
	}
	else if (strncmp(num, "MC", 2) == 0) {
		// MC\\d{12}[A-Z0-9]{11}\\d{2}
		if (len != (2 + 12 + 11 + 2)) {
			goto err;
		}

		if (!_nip24_isdigit(num, 2, 12) || !_nip24_isalnum(num, 14, 11) || !_nip24_isdigit(num, 25, 2)) {
			goto err;
		}
	}
	else if (strncmp(num, "MD", 2) == 0) {
		// MD\\d{2}[A-Z0-9]{20}
		if (len != (2 + 2 + 20)) {
			goto err;
		}

		if (!_nip24_isdigit(num, 2, 2) || !_nip24_isalnum(num, 4, 20)) {
			goto err;
		}
	}
	else if (strncmp(num, "ME", 2) == 0) {
		// ME\\d{20}
		if (len != (2 + 20)) {
			goto err;
		}

		if (!_nip24_isdigit(num, 2, 20)) {
			goto err;
		}
	}
	else if (strncmp(num, "MK", 2) == 0) {
		// MK\\d{5}[A-Z0-9]{10}\\d{2}
		if (len != (2 + 5 + 10 + 2)) {
			goto err;
		}

		if (!_nip24_isdigit(num, 2, 5) || !_nip24_isalnum(num, 7, 10) || !_nip24_isdigit(num, 17, 2)) {
			goto err;
		}
	}
	else if (strncmp(num, "MR", 2) == 0) {
		// MR\\d{25}
		if (len != (2 + 25)) {
			goto err;
		}

		if (!_nip24_isdigit(num, 2, 25)) {
			goto err;
		}
	}
	else if (strncmp(num, "MT", 2) == 0) {
		// MT\\d{2}[A-Z]{4}\\d{5}[A-Z0-9]{18}
		if (len != (2 + 2 + 4 + 5 + 18)) {
			goto err;
		}

		if (!_nip24_isdigit(num, 2, 2) || !_nip24_isalpha(num, 4, 4) || !_nip24_isdigit(num, 8, 5) || !_nip24_isalnum(num, 13, 18)) {
			goto err;
		}
	}
	else if (strncmp(num, "MU", 2) == 0) {
		// MU\\d{2}[A-Z]{4}\\d{19}[A-Z]{3}
		if (len != (2 + 2 + 4 + 19 + 3)) {
			goto err;
		}

		if (!_nip24_isdigit(num, 2, 2) || !_nip24_isalpha(num, 4, 4) || !_nip24_isdigit(num, 8, 19) || !_nip24_isalpha(num, 27, 3)) {
			goto err;
		}
	}
	else if (strncmp(num, "NL", 2) == 0) {
		// NL\\d{2}[A-Z]{4}\\d{10}
		if (len != (2 + 2 + 4 + 10)) {
			goto err;
		}

		if (!_nip24_isdigit(num, 2, 2) || !_nip24_isalpha(num, 4, 4) || !_nip24_isdigit(num, 8, 10)) {
			goto err;
		}
	}
	else if (strncmp(num, "NO", 2) == 0) {
		// NO\\d{13}
		if (len != (2 + 13)) {
			goto err;
		}

		if (!_nip24_isdigit(num, 2, 13)) {
			goto err;
		}
	}
	else if (strncmp(num, "PK", 2) == 0) {
		// PK\\d{2}[A-Z]{4}[A-Z0-9]{16}
		if (len != (2 + 2 + 4 + 16)) {
			goto err;
		}

		if (!_nip24_isdigit(num, 2, 2) || !_nip24_isalpha(num, 4, 4) || !_nip24_isalnum(num, 8, 16)) {
			goto err;
		}
	}
	else if (strncmp(num, "PL", 2) == 0) {
		// PL\\d{26}
		if (len != (2 + 26)) {
			goto err;
		}

		if (!_nip24_isdigit(num, 2, 26)) {
			goto err;
		}
	}
	else if (strncmp(num, "PS", 2) == 0) {
		// PS\\d{2}[A-Z]{4}[A-Z0-9]{21}
		if (len != (2 + 2 + 4 + 21)) {
			goto err;
		}

		if (!_nip24_isdigit(num, 2, 2) || !_nip24_isalpha(num, 4, 4) || !_nip24_isalnum(num, 8, 21)) {
			goto err;
		}
	}
	else if (strncmp(num, "PT", 2) == 0) {
		// PT\\d{23}
		if (len != (2 + 23)) {
			goto err;
		}

		if (!_nip24_isdigit(num, 2, 23)) {
			goto err;
		}
	}
	else if (strncmp(num, "QA", 2) == 0) {
		// QA\\d{2}[A-Z]{4}[A-Z0-9]{21}
		if (len != (2 + 2 + 4 + 21)) {
			goto err;
		}

		if (!_nip24_isdigit(num, 2, 2) || !_nip24_isalpha(num, 4, 4) || !_nip24_isalnum(num, 8, 21)) {
			goto err;
		}
	}
	else if (strncmp(num, "RO", 2) == 0) {
		// RO\\d{2}[A-Z]{4}[A-Z0-9]{16}
		if (len != (2 + 2 + 4 + 16)) {
			goto err;
		}

		if (!_nip24_isdigit(num, 2, 2) || !_nip24_isalpha(num, 4, 4) || !_nip24_isalnum(num, 8, 16)) {
			goto err;
		}
	}
	else if (strncmp(num, "RS", 2) == 0) {
		// RS\\d{20}
		if (len != (2 + 20)) {
			goto err;
		}

		if (!_nip24_isdigit(num, 2, 20)) {
			goto err;
		}
	}
	else if (strncmp(num, "SA", 2) == 0) {
		// SA\\d{4}[A-Z0-9]{18}
		if (len != (2 + 4 + 18)) {
			goto err;
		}

		if (!_nip24_isdigit(num, 2, 4) || !_nip24_isalnum(num, 6, 18)) {
			goto err;
		}
	}
	else if (strncmp(num, "SC", 2) == 0) {
		// SC\\d{2}[A-Z]{4}\\d{20}[A-Z]{3}
		if (len != (2 + 2 + 4 + 20 + 3)) {
			goto err;
		}

		if (!_nip24_isdigit(num, 2, 2) || !_nip24_isalpha(num, 4, 4) || !_nip24_isdigit(num, 8, 20) || !_nip24_isalpha(num, 28, 3)) {
			goto err;
		}
	}
	else if (strncmp(num, "SE", 2) == 0) {
		// SE\\d{22}
		if (len != (2 + 22)) {
			goto err;
		}

		if (!_nip24_isdigit(num, 2, 22)) {
			goto err;
		}
	}
	else if (strncmp(num, "SI", 2) == 0) {
		// SI\\d{17}
		if (len != (2 + 17)) {
			goto err;
		}

		if (!_nip24_isdigit(num, 2, 17)) {
			goto err;
		}
	}
	else if (strncmp(num, "SK", 2) == 0) {
		// SK\\d{22}
		if (len != (2 + 22)) {
			goto err;
		}

		if (!_nip24_isdigit(num, 2, 22)) {
			goto err;
		}
	}
	else if (strncmp(num, "SM", 2) == 0) {
		// SM\\d{2}[A-Z]{1}\\d{10}[A-Z0-9]{12}
		if (len != (2 + 2 + 1 + 10 + 12)) {
			goto err;
		}

		if (!_nip24_isdigit(num, 2, 2) || !_nip24_isalpha(num, 4, 1) || !_nip24_isdigit(num, 5, 10) || !_nip24_isalnum(num, 15, 12)) {
			goto err;
		}
	}
	else if (strncmp(num, "ST", 2) == 0) {
		// ST\\d{23}
		if (len != (2 + 23)) {
			goto err;
		}

		if (!_nip24_isdigit(num, 2, 23)) {
			goto err;
		}
	}
	else if (strncmp(num, "SV", 2) == 0) {
		// SV\\d{2}[A-Z]{4}\\d{20}
		if (len != (2 + 2 + 4 + 20)) {
			goto err;
		}

		if (!_nip24_isdigit(num, 2, 2) || !_nip24_isalpha(num, 4, 4) || !_nip24_isdigit(num, 8, 20)) {
			goto err;
		}
	}
	else if (strncmp(num, "TL", 2) == 0) {
		// TL\\d{21}
		if (len != (2 + 21)) {
			goto err;
		}

		if (!_nip24_isdigit(num, 2, 21)) {
			goto err;
		}
	}
	else if (strncmp(num, "TN", 2) == 0) {
		// TN\\d{22}
		if (len != (2 + 22)) {
			goto err;
		}

		if (!_nip24_isdigit(num, 2, 22)) {
			goto err;
		}
	}
	else if (strncmp(num, "TN", 2) == 0) {
		// TN\\d{22}
		if (len != (2 + 22)) {
			goto err;
		}

		if (!_nip24_isdigit(num, 2, 22)) {
			goto err;
		}
	}
	else if (strncmp(num, "TR", 2) == 0) {
		// TR\\d{8}[A-Z0-9]{16}
		if (len != (2 + 8 + 16)) {
			goto err;
		}

		if (!_nip24_isdigit(num, 2, 8) || !_nip24_isalnum(num, 10, 16)) {
			goto err;
		}
	}
	else if (strncmp(num, "UA", 2) == 0) {
		// UA\\d{8}[A-Z0-9]{19}
		if (len != (2 + 8 + 19)) {
			goto err;
		}

		if (!_nip24_isdigit(num, 2, 8) || !_nip24_isalnum(num, 10, 19)) {
			goto err;
		}
	}
	else if (strncmp(num, "VG", 2) == 0) {
		// VG\\d{2}[A-Z]{4}\\d{16}
		if (len != (2 + 2 + 4 + 16)) {
			goto err;
		}

		if (!_nip24_isdigit(num, 2, 2) || !_nip24_isalpha(num, 4, 4) || !_nip24_isdigit(num, 8, 16)) {
			goto err;
		}
	}
	else if (strncmp(num, "XK", 2) == 0) {
		// XK\\d{18}
		if (len != (2 + 18)) {
			goto err;
		}

		if (!_nip24_isdigit(num, 2, 18)) {
			goto err;
		}
	}
	else {
		goto err;
	}

	memset(sb, 0, sizeof(sb));
	memcpy(sb, num + 4, len - 4);
	memcpy(sb + len - 4, num, 4);

	memset(str, 0, sizeof(str));

	for (i = 0, p = 0; i < len; i++) {
		if (isalpha(sb[i])) {
			p += snprintf(str + p, sizeof(str), "%d", sb[i] - 55);
		}
		else {
			p += snprintf(str + p, sizeof(str), "%c", sb[i]);
		}
	}

	len = (int)strlen(str);
	chk = CHAR2NUM(str[0]);

	for (i = 1; i < len; i++) {
		chk *= 10;
		chk += CHAR2NUM(str[i]);
		chk %= 97;
	}

	ret = (chk == 1 ? TRUE : FALSE);

err:
	free(num);

	return ret;
}
