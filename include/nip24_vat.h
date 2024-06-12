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

#ifndef __NIP24_API_VAT_H__
#define __NIP24_API_VAT_H__

/////////////////////////////////////////////////////////////////

#define NIP24_VAT_NOT_REGISTERED        1
#define NIP24_VAT_ACTIVE                2
#define NIP24_VAT_EXEMPTED              3

/////////////////////////////////////////////////////////////////

/**
 * Status firmy w rejestrze VAT
 */
typedef struct VATStatus {
	char* UID;

	char* NIP;
	char* REGON;
	char* Name;
	
	int Status;
	char* Result;

	char* ID;
	time_t Date;
	char* Source;
} VATStatus;

/////////////////////////////////////////////////////////////////

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Utworzenie nowego obiektu z danymi
 * @param vat adres na utworzony obiekt
 */
NIP24_API BOOL vatstatus_new(VATStatus** vat);

/**
 * Dealokacja obiektu z danymi
 * @param vat adres na utworzony obiekt
 */
NIP24_API void vatstatus_free(VATStatus** vat);

#ifdef __cplusplus
}
#endif

/////////////////////////////////////////////////////////////////

#endif
