/**
 * Copyright 2015-2020 NETCAT (www.netcat.pl)
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
 * @copyright 2015-2020 NETCAT (www.netcat.pl)
 * @license http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef __NIP24_API_ACCOUNT_H__
#define __NIP24_API_ACCOUNT_H__

/////////////////////////////////////////////////////////////////

/**
 * Dane konta uzytkownika
 */
typedef struct AccountStatus {
	char* UID;

	char* Type;
	time_t ValidTo;
	char* BillingPlanName;

	double SubscriptionPrice;
	double ItemPrice;
	double ItemPriceStatus;
	double ItemPriceInvoice;
	double ItemPriceAll;
	double ItemPriceIBAN;
	double ItemPriceWhitelist;
	double ItemPriceSearchVAT;

	int Limit;
	int RequestDelay;
	int DomainLimit;

	BOOL OverPlanAllowed;
	BOOL TerytCodes;
	BOOL ExcelAddIn;
	BOOL JPKVAT;
	BOOL Stats;
	BOOL NIPMonitor;
	BOOL SearchByNIP;
	BOOL SearchByREGON;
	BOOL SearchByKRS;
	BOOL FuncIsActive;
	BOOL FuncGetInvoiceData;
	BOOL FuncGetAllData;
	BOOL FuncGetVIESData;
	BOOL FuncGetVATStatus;
	BOOL FuncGetIBANStatus;
	BOOL FuncGetWhitelistStatus;
	BOOL FuncSearchVAT;

	int InvoiceDataCount;
	int AllDataCount;
	int FirmStatusCount;
	int VATStatusCount;
	int VIESStatusCount;
	int IBANStatusCount;
	int WhitelistStatusCount;
	int SearchVATCount;
	int TotalCount;
} AccountStatus;

/////////////////////////////////////////////////////////////////

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Utworzenie nowego obiektu z danymi
 * @param account adres na utworzony obiekt
 */
NIP24_API BOOL accountstatus_new(AccountStatus** account);

/**
 * Dealokacja obiektu z danymi
 * @param account adres na utworzony obiekt
 */
NIP24_API void accountstatus_free(AccountStatus** account);

#ifdef __cplusplus
}
#endif

/////////////////////////////////////////////////////////////////

#endif
