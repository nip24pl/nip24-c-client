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

#ifndef __NIP24_API_VATENTITY_H__
#define __NIP24_API_VATENTITY_H__

/////////////////////////////////////////////////////////////////

/**
 * Dane osoby z rejestru VAT
 */
typedef struct VATPerson {
    char* CompanyName;
    char* FirstName;
    char* LastName;
    char* NIP;
} VATPerson;

/////////////////////////////////////////////////////////////////

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Utworzenie nowego obiektu z danymi
 * @param vat adres na utworzony obiekt
 */
NIP24_API BOOL vatperson_new(VATPerson** person);

/**
 * Dealokacja obiektu z danymi
 * @param vat adres na utworzony obiekt
 */
NIP24_API void vatperson_free(VATPerson** person);

#ifdef __cplusplus
}
#endif

/////////////////////////////////////////////////////////////////

/**
 * Dane podmiotu z rejestru VAT
 */
typedef struct VATEntity {
    char* Name;
    char* NIP;
    char* REGON;
    char* KRS;

    char* ResidenceAddress;
    char* WorkingAddress;

    int VATStatus;
    char* VATResult;

    VATPerson** Representatives;
    int RepresentativesCount;

    VATPerson** AuthorizedClerks;
    int AuthorizedClerksCount;

    VATPerson** Partners;
    int PartnersCount;

    char** IBANs;
    int IBANsCount;

    BOOL HasVirtualAccounts;

    time_t RegistrationLegalDate;
    time_t RegistrationDenialDate;
    char* RegistrationDenialBasis;
    time_t RestorationDate;
    char* RestorationBasis;
    time_t RemovalDate;
    char* RemovalBasis;
} VATEntity;

/////////////////////////////////////////////////////////////////

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Utworzenie nowego obiektu z danymi
 * @param vat adres na utworzony obiekt
 */
NIP24_API BOOL vatentity_new(VATEntity** entity);

/**
 * Dealokacja obiektu z danymi
 * @param vat adres na utworzony obiekt
 */
NIP24_API void vatentity_free(VATEntity** entity);

#ifdef __cplusplus
}
#endif

/////////////////////////////////////////////////////////////////

#endif
