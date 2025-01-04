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

#ifndef __NIP24_API_BUSINESS_PARTNER_H__
#define __NIP24_API_BUSINESS_PARTNER_H__

/////////////////////////////////////////////////////////////////

/**
 * Dane wspólnika
 */
typedef struct BusinessPartner {
	char* REGON;
	char* FirmName;
	char* FirstName;
	char* SecondName;
	char* LastName;
} BusinessPartner;

/////////////////////////////////////////////////////////////////

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Utworzenie nowego obiektu z danymi
 * @param bp adres na utworzony obiekt
 */
NIP24_API BOOL businesspartner_new(BusinessPartner** bp);

/**
 * Dealokacja obiektu z danymi
 * @param bp adres na utworzony obiekt
 */
NIP24_API void businesspartner_free(BusinessPartner** bp);

#ifdef __cplusplus
}
#endif

/////////////////////////////////////////////////////////////////

#endif
