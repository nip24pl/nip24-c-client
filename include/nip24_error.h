/**
 * Copyright 2015-2024 NETCAT (www.netcat.pl)
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
 * @copyright 2015-2024 NETCAT (www.netcat.pl)
 * @license http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef __NIP24_API_ERROR_H__
#define __NIP24_API_ERROR_H__

/////////////////////////////////////////////////////////////////

#define NIP24_ERR_NIP_EMPTY               1
#define NIP24_ERR_NIP_UNKNOWN             2
#define NIP24_ERR_GUS_LOGIN               3
#define NIP24_ERR_GUS_CAPTCHA             4
#define NIP24_ERR_GUS_SYNC                5
#define NIP24_ERR_NIP_UPDATE              6
#define NIP24_ERR_NIP_BAD                 7
#define NIP24_ERR_CONTENT_SYNTAX          8
#define NIP24_ERR_NIP_NOT_ACTIVE          9
#define NIP24_ERR_INVALID_PATH            10
#define NIP24_ERR_EXCEPTION               11
#define NIP24_ERR_NO_PERMISSION           12
#define NIP24_ERR_GEN_INVOICES            13
#define NIP24_ERR_GEN_SPEC_INV            14
#define NIP24_ERR_SEND_INVOICE            15
#define NIP24_ERR_PREMIUM_FEATURE         16
#define NIP24_ERR_SEND_ANNOUNCEMENT       17
#define NIP24_ERR_INVOICE_PAYMENT         18
#define NIP24_ERR_REGON_BAD               19
#define NIP24_ERR_SEARCH_KEY_EMPTY        20
#define NIP24_ERR_KRS_BAD                 21
#define NIP24_ERR_EUVAT_BAD               22
#define NIP24_ERR_VIES_SYNC               23
#define NIP24_ERR_CEIDG_SYNC              24
#define NIP24_ERR_RANDOM_NUMBER           25
#define NIP24_ERR_PLAN_FEATURE            26
#define NIP24_ERR_SEARCH_TYPE             27
#define NIP24_ERR_PPUMF_SYNC              28
#define NIP24_ERR_PPUMF_DIRECT            29
#define NIP24_ERR_NIP_FEATURE             30
#define NIP24_ERR_REGON_FEATURE           31
#define NIP24_ERR_KRS_FEATURE             32
#define NIP24_ERR_TEST_MODE               33
#define NIP24_ERR_ACTIVITY_CHECK          34
#define NIP24_ERR_ACCESS_DENIED           35
#define NIP24_ERR_MAINTENANCE             36
#define NIP24_ERR_BILLING_PLANS           37
#define NIP24_ERR_DOCUMENT_PDF            38
#define NIP24_ERR_EXPORT_PDF              39
#define NIP24_ERR_RANDOM_TYPE             40
#define NIP24_ERR_LEGAL_FORM              41
#define NIP24_ERR_GROUP_CHECKS            42
#define NIP24_ERR_CLIENT_COUNTERS         43
#define NIP24_ERR_URE_SYNC                44
#define NIP24_ERR_URE_DATA                45
#define NIP24_ERR_DKN_BAD                 46
#define NIP24_ERR_SEND_REMAINDER          47
#define NIP24_ERR_EXPORT_JPK              48
#define NIP24_ERR_GEN_ORDER_INV           49
#define NIP24_ERR_SEND_EXPIRATION         50
#define NIP24_ERR_IBAN_SYNC               51
#define NIP24_ERR_ORDER_CANCEL            52
#define NIP24_ERR_WHITELIST_CHECK         53
#define NIP24_ERR_AUTH_TIMESTAMP          54
#define NIP24_ERR_AUTH_MAC                55
#define NIP24_ERR_IBAN_BAD                56

#define NIP24_ERR_DB_AUTH_IP              101
#define NIP24_ERR_DB_AUTH_KEY_STATUS      102
#define NIP24_ERR_DB_AUTH_KEY_VALUE       103
#define NIP24_ERR_DB_AUTH_OVER_PLAN       104
#define NIP24_ERR_DB_CLIENT_LOCKED        105
#define NIP24_ERR_DB_CLIENT_TYPE          106
#define NIP24_ERR_DB_CLIENT_NOT_PAID      107
#define NIP24_ERR_DB_AUTH_KEYID_VALUE     108

#define NIP24_ERR_CLI_CONNECT             201
#define NIP24_ERR_CLI_RESPONSE            202
#define NIP24_ERR_CLI_NUMBER              203
#define NIP24_ERR_CLI_NIP                 204
#define NIP24_ERR_CLI_REGON               205
#define NIP24_ERR_CLI_KRS                 206
#define NIP24_ERR_CLI_EUVAT               207
#define NIP24_ERR_CLI_IBAN                208
#define NIP24_ERR_CLI_EXCEPTION           209
#define NIP24_ERR_CLI_DATEFORMAT          210
#define NIP24_ERR_CLI_INPUT               211

/////////////////////////////////////////////////////////////////

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Pobranie komunikatu bledu
 * @param code kod bledu
 * @return komunikat
 */
NIP24_API const char* nip24_errstr(int code);

#ifdef __cplusplus
}
#endif

/////////////////////////////////////////////////////////////////

#endif
