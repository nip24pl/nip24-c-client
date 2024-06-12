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

#ifndef __NIP24_API_ALL_H__
#define __NIP24_API_ALL_H__

/////////////////////////////////////////////////////////////////

/**
 * Pelne dane firmy
 */
typedef struct AllData {
	char* UID;

	char* Type;
	char* NIP;
	char* REGON;

	char* Name;
	char* ShortName;
	char* FirstName;
	char* SecondName;
	char* LastName;

	char* Street;
	char* StreetCode;
	char* StreetNumber;
	char* HouseNumber;
	char* City;
	char* CityCode;
	char* Community;
	char* CommunityCode;
	char* County;
	char* CountyCode;
	char* State;
	char* StateCode;
	char* PostCode;
	char* PostCity;

	char* Phone;
	char* Email;
	char* WWW;

	time_t CreationDate;
	time_t StartDate;
	time_t RegistrationDate;
	time_t HoldDate;
	time_t RenevalDate;
	time_t LastUpdateDate;
	time_t EndDate;

	char* RegistryEntityCode;
	char* RegistryEntityName;

	char* RegistryCode;
	char* RegistryName;

	time_t RecordCreationDate;
	char* RecordNumber;

	char* BasicLegalFormCode;
	char* BasicLegalFormName;

	char* SpecificLegalFormCode;
	char* SpecificLegalFormName;

	char* OwnershipFormCode;
	char* OwnershipFormName;

	BusinessPartner** BusinessPartner;
	int BusinessPartnerCount;

	PKD** PKD;
	int PKDCount;
} AllData;

/////////////////////////////////////////////////////////////////

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Utworzenie nowego obiektu z danymi
 * @param all adres na utworzony obiekt
 */
NIP24_API BOOL alldata_new(AllData** all);

/**
 * Dealokacja obiektu z danymi
 * @param all adres na utworzony obiekt
 */
NIP24_API void alldata_free(AllData** all);

#ifdef __cplusplus
}
#endif

/////////////////////////////////////////////////////////////////

#endif
