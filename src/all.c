/**
 * Copyright 2015-2023 NETCAT (www.netcat.pl)
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
 * @copyright 2015-2023 NETCAT (www.netcat.pl)
 * @license http://www.apache.org/licenses/LICENSE-2.0
 */

#include "internal.h"
#include "nip24.h"


NIP24_API BOOL alldata_new(AllData** all)
{
	AllData* ad = NULL;

	BOOL ret = FALSE;

	if ((ad = (AllData*)malloc(sizeof(AllData))) == NULL) {
		goto err;
	}

	memset(ad, 0, sizeof(AllData));

	// ok
	*all = ad;
	ad = NULL;

	ret = TRUE;

err:
	alldata_free(&ad);

	return ret;
}

NIP24_API void alldata_free(AllData** all)
{
	AllData* ad = (all ? *all : NULL);

	int i;

	if (ad) {
		free(ad->UID);

		free(ad->Type);
		free(ad->NIP);
		free(ad->REGON);

		free(ad->Name);
		free(ad->ShortName);
		free(ad->FirstName);
		free(ad->SecondName);
		free(ad->LastName);

		free(ad->Street);
		free(ad->StreetCode);
		free(ad->StreetNumber);
		free(ad->HouseNumber);
		free(ad->City);
		free(ad->CityCode);
		free(ad->Community);
		free(ad->CommunityCode);
		free(ad->County);
		free(ad->CountyCode);
		free(ad->State);
		free(ad->StateCode);
		free(ad->PostCode);
		free(ad->PostCity);

		free(ad->Phone);
		free(ad->Email);
		free(ad->WWW);

		free(ad->RegistryEntityCode);
		free(ad->RegistryEntityName);

		free(ad->RegistryCode);
		free(ad->RegistryName);

		free(ad->RecordNumber);

		free(ad->BasicLegalFormCode);
		free(ad->BasicLegalFormName);

		free(ad->SpecificLegalFormCode);
		free(ad->SpecificLegalFormName);

		free(ad->OwnershipFormCode);
		free(ad->OwnershipFormName);

		for (i = 0; i < ad->PKDCount; i++) {
			pkd_free(&ad->PKD[i]);
		}

		free(ad->PKD);

		free(*all);
		*all = NULL;
	}
}
