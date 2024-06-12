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

#ifndef __NIP24_API_WHITELIST_H__
#define __NIP24_API_WHITELIST_H__

/////////////////////////////////////////////////////////////////

/**
 * Status podmiotu na bia³ej liœcie
 */
typedef struct WLStatus {
	char* UID;

	char* NIP;
	char* IBAN;
	
	BOOL Valid;
	BOOL Virtual;

	int Status;
	char* Result;

	int HashIndex;
	int MaskIndex;
	time_t Date;
	char* Source;
} WLStatus;

/////////////////////////////////////////////////////////////////

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Utworzenie nowego obiektu z danymi
 * @param wl adres na utworzony obiekt
 */
NIP24_API BOOL wlstatus_new(WLStatus** wl);

/**
 * Dealokacja obiektu z danymi
 * @param wl adres na utworzony obiekt
 */
NIP24_API void wlstatus_free(WLStatus** wl);

#ifdef __cplusplus
}
#endif

/////////////////////////////////////////////////////////////////

#endif
