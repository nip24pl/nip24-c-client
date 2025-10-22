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

#ifndef __NIP24_API_CLIENT_H__
#define __NIP24_API_CLIENT_H__

/////////////////////////////////////////////////////////////////

#define NIP24_VERSION			"1.4.2"

#define NIP24_PRODUCTION_URL	"https://www.nip24.pl/api"

#define NIP24_TEST_URL			"https://www.nip24.pl/api-test"
#define NIP24_TEST_ID			"test_id"
#define NIP24_TEST_KEY			"test_key"

/////////////////////////////////////////////////////////////////

/**
 * Typy numerow identyfikujacych firme
 */
typedef enum Number {
	NIP = 1,
	REGON,
	KRS,
	EUVAT,
    IBAN
} Number;

/////////////////////////////////////////////////////////////////

/**
 * Klient serwisu NIP24
 */
typedef struct NIP24Client {
	char* url;
	char* id;
	char* key;

	char* app;

    int err_code;
	char* err;
} NIP24Client;

/////////////////////////////////////////////////////////////////

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Utworzenie nowego obiektu klienta
 * @param nip24 adres na utworzony obiekt klienta
 * @param url adres URL serwisu NIP24
 * @param id identyfikator klucza klienta serwisu
 * @param key klucz klienta serwisu
 * @return wartosc NIP24_OK lub kod bledu
 */
NIP24_API BOOL nip24_new(NIP24Client** nip24, const char* url, const char* id, const char* key);

/**
 * Utworzenie nowego obiektu klienta serwisu produkcyjnego
 * @param nip24 adres na utworzony obiekt klienta
 * @param id identyfikator klucza klienta serwisu
 * @param key klucz klienta serwisu
 * @return wartosc NIP24_OK lub kod bledu
 */
NIP24_API BOOL nip24_new_prod(NIP24Client** nip24, const char* id, const char* key);

/**
 * Utworzenie nowego obiektu klienta serwisu testowego
 * @param nip24 adres na utworzony obiekt klienta
 * @return wartosc NIP24_OK lub kod bledu
 */
NIP24_API BOOL nip24_new_test(NIP24Client** nip24);

/**
 * Dealokacja obiektu klienta
 * @param nip24 adres na utworzony obiekt klienta
 */
NIP24_API void nip24_free(NIP24Client** nip24);

/**
 * Ostatni kod bledu
 * @param nip24 adres na obiekt klienta
 * @return kod bledu
 */
NIP24_API int nip24_get_last_err_code(NIP24Client* nip24);

/**
 * Ostatni komunikat bledu
 * @param nip24 adres na obiekt klienta
 * @return opis bledu lub NULL
 */
NIP24_API char* nip24_get_last_err(NIP24Client* nip24);

/**
 * Sprawdzenie czy firma prowadzi aktywna dzialalnosc
 * @param nip24 adres obiektu klienta
 * @param type typ numeru identyfikujacego firme
 * @param number numer okreslonego typu
 * @return TRUE jezeli firma prowadzi aktywna dzia³alnosc, FALSE jezeli firma zakonczyla dzialalnosc
 */
NIP24_API BOOL nip24_is_active(NIP24Client* nip24, Number type, const char* number);

/**
 * Sprawdzenie czy firma prowadzi aktywna dzialalnosc
 * @param nip24 adres obiektu klienta
 * @param nip numer NIP
 * @return TRUE jezeli firma prowadzi aktywna dzia³alnosc, FALSE jezeli firma zakonczyla dzialalnosc
 */
NIP24_API BOOL nip24_is_active_nip(NIP24Client* nip24, const char* nip);

/**
 * Pobranie podstawowych danych firmy do faktury
 * @param nip24 adres obiektu klienta
 * @param type typ numeru identyfikujacego firme
 * @param number numer okreslonego typu
 * @param force parametr ignorowany, zostawiony dla zachowania kompatybilnosci wstecznej
 * @return dane firmy lub NULL w przypadku bledu
 */
NIP24_API InvoiceData* nip24_get_invoice_data(NIP24Client* nip24, Number type, const char* number, BOOL force);

/**
 * Pobranie podstawowych danych firmy do faktury
 * @param nip24 adres obiektu klienta
 * @param nip numer NIP
 * @param force parametr ignorowany, zostawiony dla zachowania kompatybilnosci wstecznej
 * @return dane firmy lub NULL w przypadku bledu
 */
NIP24_API InvoiceData* nip24_get_invoice_data_nip(NIP24Client* nip24, const char* nip, BOOL force);

/**
 * Pobranie szczegolowych danych firmy
 * @param nip24 adres obiektu klienta
 * @param type typ numeru identyfikujacego firme
 * @param number numer okreslonego typu
 * @param force parametr ignorowany, zostawiony dla zachowania kompatybilnosci wstecznej
 * @return dane firmy lub NULL w przypadku bledu
 */
NIP24_API AllData* nip24_get_all_data(NIP24Client* nip24, Number type, const char* number, BOOL force);

/**
 * Pobranie szczegolowych danych firmy
 * @param nip24 adres obiektu klienta
 * @param nip numer NIP
 * @param force parametr ignorowany, zostawiony dla zachowania kompatybilnosci wstecznej
 * @return dane firmy lub NULL w przypadku bledu
 */
NIP24_API AllData* nip24_get_all_data_nip(NIP24Client* nip24, const char* nip, BOOL force);

/**
 * Pobranie danych firmy z systemu VIES
 * @param nip24 adres obiektu klienta
 * @param euvat numer EU VAT ID
 * @return dane firmy lub NULL w przypadku bledu
 */
NIP24_API VIESData* nip24_get_vies_data(NIP24Client* nip24, const char* euvat);

/**
 * Sprawdzenie statusu firmy w rejestrze VAT
 * @param nip24 adres obiektu klienta
 * @param type typ numeru identyfikujacego firme
 * @param number numer okreslonego typu
 * @param direct parametr ignorowany, zostawiony dla zachowania kompatybilnosci wstecznej
 * @return dane firmy lub NULL w przypadku bledu
 */
NIP24_API VATStatus* nip24_get_vat_status(NIP24Client* nip24, Number type, const char* number, BOOL direct);

/**
 * Sprawdzenie statusu firmy w rejestrze VAT
 * @param nip24 adres obiektu klienta
 * @param nip numer NIP
 * @param direct parametr ignorowany, zostawiony dla zachowania kompatybilnosci wstecznej
 * @return dane firmy lub NULL w przypadku bledu
 */
NIP24_API VATStatus* nip24_get_vat_status_nip(NIP24Client* nip24, const char* nip, BOOL direct);

/**
 * Sprawdzenie statusu rachunku bankowego firmy
 * @param nip24 adres obiektu klienta
 * @param type typ numeru identyfikujacego firme
 * @param number numer okreslonego typu
 * @param iban numer IBAN rachunku do sprawdzenia (polskie rachunki moga byc bez prefiksu PL)
 * @param date dzien, ktorego ma dotyczyc sprawdzenie statusu (0 - biezacy dzien)
 * @return dane firmy lub NULL w przypadku bledu
 */
NIP24_API IBANStatus* nip24_get_iban_status(NIP24Client* nip24, Number type, const char* number, const char* iban, time_t date);

/**
 * Sprawdzenie statusu rachunku bankowego firmy
 * @param nip24 adres obiektu klienta
 * @param nip numer NIP
 * @param iban numer IBAN rachunku do sprawdzenia (polskie rachunki moga byc bez prefiksu PL)
 * @param date dzien, ktorego ma dotyczyc sprawdzenie statusu (0 - biezacy dzien)
 * @return dane firmy lub NULL w przypadku bledu
 */
NIP24_API IBANStatus* nip24_get_iban_status_nip(NIP24Client* nip24, const char* nip, const char* iban, time_t date);

/**
 * Sprawdzenie statusu firmy na podstawie pliku bia³ej listy podatników VAT
 * @param nip24 adres obiektu klienta
 * @param type typ numeru identyfikujacego firme
 * @param number numer okreslonego typu
 * @param iban numer IBAN rachunku do sprawdzenia (polskie rachunki moga byc bez prefiksu PL)
 * @param date dzien, ktorego ma dotyczyc sprawdzenie statusu (0 - biezacy dzien)
 * @return dane firmy lub NULL w przypadku bledu
 */
NIP24_API WLStatus* nip24_get_whitelist_status(NIP24Client* nip24, Number type, const char* number, const char* iban, time_t date);

/**
 * Sprawdzenie statusu firmy na podstawie pliku bia³ej listy podatników VAT
 * @param nip24 adres obiektu klienta
 * @param nip numer NIP
 * @param iban numer IBAN rachunku do sprawdzenia (polskie rachunki moga byc bez prefiksu PL)
 * @param date dzien, ktorego ma dotyczyc sprawdzenie statusu (0 - biezacy dzien)
 * @return dane firmy lub NULL w przypadku bledu
 */
NIP24_API WLStatus* nip24_get_whitelist_status_nip(NIP24Client* nip24, const char* nip, const char* iban, time_t date);

/**
 * Wyszukiwanie danych w rejestrze VAT
 * @param nip24 adres obiektu klienta
 * @param type typ numeru identyfikujacego firme
 * @param number numer okreslonego typu
 * @param date dzien, ktorego ma dotyczyc wyszukiwanie (0 - biezacy dzien)
 * @return wyszukane dane lub NULL w przypadku bledu
 */
NIP24_API SearchResult* nip24_search_vat_registry(NIP24Client* nip24, Number type, const char* number, time_t date);

/**
 * Wyszukiwanie danych w rejestrze VAT
 * @param nip24 adres obiektu klienta
 * @param nip numer NIP
 * @param date dzien, ktorego ma dotyczyc wyszukiwanie (0 - biezacy dzien)
 * @return wyszukane dane lub NULL w przypadku bledu
 */
NIP24_API SearchResult* nip24_search_vat_registry_nip(NIP24Client* nip24, const char* nip, time_t date);

/**
 * Sprawdzenie biezacego stanu konta uzytkownika
 * @param nip24 adres obiektu klienta
 * @return status konta lub NULL w przypadku bledu
 */
NIP24_API AccountStatus* nip24_get_account_status(NIP24Client* nip24);

#ifdef __cplusplus
}
#endif

/////////////////////////////////////////////////////////////////

#endif
