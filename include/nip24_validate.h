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

#ifndef __NIP24_API_VALIDATE_H__
#define __NIP24_API_VALIDATE_H__

/////////////////////////////////////////////////////////////////

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Konwertuje podany numer NIP do postaci znormalizowanej
 * @param nip numer NIP w dowolnym formacie
 * @return adres na nowy, znormalizowany numer NIP lub NULL
 */
NIP24_API char* nip24_nip_normalize(const char* nip);

/**
 * Sprawdza poprawnosc numeru NIP
 * @param nip numer NIP w dowolnym formacie
 * @return TRUE jezeli podany numer jest prawidlowy
 */
NIP24_API BOOL nip24_nip_is_valid(const char* nip);

/**
 * Konwertuje podany numer REGON do postaci znormalizowanej
 * @param regon numer REGON w dowolnym formacie
 * @return adres na nowy, znormalizowany numer REGON lub NULL
 */
NIP24_API char* nip24_regon_normalize(const char* regon);

/**
 * Sprawdza poprawnosc numeru REGON
 * @param regon numer REGON w dowolnym formacie
 * @return TRUE jezeli podany numer jest prawidlowy
 */
NIP24_API BOOL nip24_regon_is_valid(const char* regon);

/**
 * Konwertuje podany numer KRS do postaci znormalizowanej
 * @param krs numer KRS w dowolnym formacie
 * @return adres na nowy, znormalizowany numer KRS lub NULL
 */
NIP24_API char* nip24_krs_normalize(const char* krs);

/**
 * Sprawdza poprawnosc numeru KRS
 * @param krs numer KRS w dowolnym formacie
 * @return TRUE jezeli podany numer jest prawidlowy
 */
NIP24_API BOOL nip24_krs_is_valid(const char* krs);

/**
 * Konwertuje podany numer EU VAT ID do postaci znormalizowanej
 * @param euvat numer EU VAT ID w dowolnym formacie
 * @return adres na nowy, znormalizowany numer EU VAT ID lub NULL
 */
NIP24_API char* nip24_euvat_normalize(const char* euvat);

/**
 * Sprawdza poprawnosc numeru EU VAT ID
 * @param euvat numer EU VAT ID w dowolnym formacie
 * @return TRUE jezeli podany numer jest prawidlowy
 */
NIP24_API BOOL nip24_euvat_is_valid(const char* euvat);

/**
 * Konwertuje podany numer IBAN do postaci znormalizowanej
 * @param euvat numer IBAN w dowolnym formacie
 * @return adres na nowy, znormalizowany numer IBAN lub NULL
 */
NIP24_API char* nip24_iban_normalize(const char* iban);

/**
 * Sprawdza poprawnosc numeru IBAN
 * @param euvat numer IBAN w dowolnym formacie
 * @return TRUE jezeli podany numer jest prawidlowy
 */
NIP24_API BOOL nip24_iban_is_valid(const char* iban);

#ifdef __cplusplus
}
#endif

/////////////////////////////////////////////////////////////////

#endif
