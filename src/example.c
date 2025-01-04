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

#pragma warning(disable: 4333 4996)

#define _CRT_SECURE_NO_DEPRECATE
#define _WIN32_WINNT	0x0400

#include <windows.h>
#include <stdio.h>

#include "nip24.h"

int main()
{
	NIP24Client* nip24 = NULL;
	
	AccountStatus* account = NULL;
	AllData* all = NULL;
	InvoiceData* invoice = NULL;
	VATStatus* vat = NULL;
	VIESData* vies = NULL;
	IBANStatus* iban = NULL;
	WLStatus* whitelist = NULL;
	SearchResult* result = NULL;

	BOOL active;

	const char* nip = "7171642051";
	const char* nip_eu = "PL7171642051";
	const char* account_number = "49154000046458439719826658";

	// Utworzenie obiektu klienta us³ugi serwisu produkcyjnego
	// id – ci¹g znaków reprezentuj¹cy identyfikator klucza API
	// key – ci¹g znaków reprezentuj¹cy klucz API
	// nip24_new_prod(&nip24, "id", "key");

	// Utworzenie obiektu klienta us³ugi serwisu testowego
	if (!nip24_new_test(&nip24)) {
		goto err;
	}

	// Sprawdzenie stanu konta
	account = nip24_get_account_status(nip24);

	if (account != NULL) {
		printf("Nazwa planu: %s\n", account->BillingPlanName);
		printf("Cena: %.2f\n", account->SubscriptionPrice);
		printf("Iloœæ zapytañ: %d\n", account->TotalCount);
	}
	else {
		printf("B³¹d: %s (kod: %d)\n", nip24_get_last_err(nip24), nip24_get_last_err_code(nip24));
	}

	// Sprawdzenie statusu fimy
	active = nip24_is_active(nip24, NIP, nip);

	if (active) {
		printf("Firma prowadzi aktywn¹ dzia³alnoœæ");
	}
	else {
		if (nip24_get_last_err(nip24) == NULL) {
			printf("Firma zawiesi³a lub zakoñczy³a dzia³alnoœæ");
		}
		else {
			printf("B³¹d: %s (kod: %d)\n", nip24_get_last_err(nip24), nip24_get_last_err_code(nip24));
		}
	}

	// Sprawdzenie statusu firmy w rejestrze VAT
	vat = nip24_get_vat_status(nip24, NIP, nip, TRUE);

	if (vat != NULL) {
		printf("NIP: %s\n", vat->NIP);
		printf("REGON: %s\n", vat->REGON);
		printf("Nazwa firmy: %s\n", vat->Name);
		printf("Status: %d\n", vat->Status);
		printf("Wynik: %s\n", vat->Result);
	}
	else {
		printf("B³¹d: %s (kod: %d)\n", nip24_get_last_err(nip24), nip24_get_last_err_code(nip24));
	}

	// Wywo³anie metody zwracaj¹cej dane do faktury
	invoice = nip24_get_invoice_data(nip24, NIP, nip, FALSE);

	if (invoice != NULL) {
		printf("Nazwa: %s\n", invoice->Name);
		printf("Imiê i nazwisko: %s %s\n", invoice->FirstName, invoice->LastName);
		printf("Adres: %s %s %s %s\n", invoice->PostCode, invoice->PostCity, invoice->Street, invoice->StreetNumber);
		printf("NIP: %s\n", invoice->NIP);
	}
	else {
		printf("B³¹d: %s (kod: %d)\n", nip24_get_last_err(nip24), nip24_get_last_err_code(nip24));
	}

	// Wywo³anie metody zwracaj¹cej szczegó³owe dane firmy
	all = nip24_get_all_data(nip24, NIP, nip, FALSE);

	if (all != NULL) {
		printf("Nazwa: %s\n", all->Name);
		printf("Imiê i nazwisko: %s %s\n", all->FirstName, all->LastName);
		printf("Adres: %s %s %s %s\n", all->PostCode, all->PostCity, all->Street, all->StreetNumber);
		printf("NIP: %s\n", all->NIP);
	}
	else {
		printf("B³¹d: %s (kod: %d)\n", nip24_get_last_err(nip24), nip24_get_last_err_code(nip24));
	}

	// Wywo³anie metody zwracaj¹cej dane z systemu VIES
	vies = nip24_get_vies_data(nip24, nip_eu);

	if (vies != NULL) {
		printf("Kraj: %s\n", vies->CountryCode);
		printf("VAT ID: %s\n", vies->VATNumber);
		printf("Aktywny: %d\n", vies->Valid);
	}
	else {
		printf("B³¹d: %s (kod: %d)\n", nip24_get_last_err(nip24), nip24_get_last_err_code(nip24));
	}

	// Wywo³anie metody zwracaj¹cej informacje o rachunku bankowym
	iban = nip24_get_iban_status(nip24, NIP, nip, account_number, 0);

	if (iban != NULL) {
		printf("NIP: %s\n", iban->NIP);
		printf("IBAN: %s\n", iban->IBAN);
		printf("Aktywny: %d\n", iban->Valid);
	}
	else {
		printf("B³¹d: %s (kod: %d)\n", nip24_get_last_err(nip24), nip24_get_last_err_code(nip24));
	}

	// Wywo³anie metody sprawdzaj¹cej status podmiotu na bia³ej liœcie podatników VAT
	whitelist = nip24_get_whitelist_status(nip24, NIP, nip, account_number, 0);

	if (whitelist != NULL) {
		printf("NIP: %s\n", whitelist->NIP);
		printf("IBAN: %s\n", whitelist->IBAN);
		printf("Aktywny: %d\n", whitelist->Valid);
	}
	else {
		printf("B³¹d: %s (kod: %d)\n", nip24_get_last_err(nip24), nip24_get_last_err_code(nip24));
	}

	// Wywo³anie metody wyszukuj¹cej dane w rejestrze VAT
	result = nip24_search_vat_registry(nip24, NIP, nip, 0);

	if (result != NULL) {
		printf("Wyniki: %d\n", result->ResultsCount);

		if (result->ResultsCount > 0) {
			printf("Nazwa: %s\n", result->Results.VATEntity[0]->Name);
			printf("NIP: %s\n", result->Results.VATEntity[0]->NIP);

			if (result->Results.VATEntity[0]->IBANsCount > 0) {
				printf("IBAN: %s\n", result->Results.VATEntity[0]->IBANs[0]);
			}

			printf("Status: %d\n", result->Results.VATEntity[0]->VATStatus);
			printf("Wynik: %s\n", result->Results.VATEntity[0]->VATResult);
		}
	}
	else {
		printf("B³¹d: %s (kod: %d)\n", nip24_get_last_err(nip24), nip24_get_last_err_code(nip24));
	}

err:
	nip24_free(&nip24);

	accountstatus_free(&account);
	alldata_free(&all);
	invoicedata_free(&invoice);
	vatstatus_free(&vat);
	viesdata_free(&vies);
	ibanstatus_free(&iban);
	wlstatus_free(&whitelist);
	searchresult_free(&result);

	return 0;
}

