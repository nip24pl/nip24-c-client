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


NIP24_API BOOL vatperson_new(VATPerson** person)
{
	VATPerson* vp = NULL;

	BOOL ret = FALSE;

	if ((vp = (VATPerson*)malloc(sizeof(VATPerson))) == NULL) {
		goto err;
	}

	memset(vp, 0, sizeof(VATPerson));

	// ok
	*person = vp;
	vp = NULL;

	ret = TRUE;

err:
	vatperson_free(&vp);

	return ret;
}

NIP24_API void vatperson_free(VATPerson** person)
{
	VATPerson* vp = (person ? *person : NULL);

	if (vp) {
		free(vp->CompanyName);
		free(vp->FirstName);
		free(vp->LastName);
		free(vp->NIP);

		free(*person);
		*person = NULL;
	}
}

NIP24_API BOOL vatentity_new(VATEntity** entity)
{
	VATEntity* ve = NULL;

	BOOL ret = FALSE;

	if ((ve = (VATEntity*)malloc(sizeof(VATEntity))) == NULL) {
		goto err;
	}

	memset(ve, 0, sizeof(VATEntity));

	// ok
	*entity = ve;
	ve = NULL;

	ret = TRUE;

err:
	vatentity_free(&ve);

	return ret;
}

NIP24_API void vatentity_free(VATEntity** entity)
{
	VATEntity* ve = (entity ? *entity : NULL);

	int i;

	if (ve) {
		free(ve->Name);
		free(ve->NIP);
		free(ve->REGON);
		free(ve->KRS);

		free(ve->ResidenceAddress);
		free(ve->WorkingAddress);

		free(ve->VATResult);

		for (i = 0; i < ve->RepresentativesCount; i++) {
			vatperson_free(&ve->Representatives[i]);
		}

		free(ve->Representatives);

		for (i = 0; i < ve->AuthorizedClerksCount; i++) {
			vatperson_free(&ve->AuthorizedClerks[i]);
		}

		free(ve->AuthorizedClerks);

		for (i = 0; i < ve->PartnersCount; i++) {
			vatperson_free(&ve->Partners[i]);
		}

		free(ve->Partners);

		for (i = 0; i < ve->IBANsCount; i++) {
			free(ve->IBANs[i]);
		}

		free(ve->IBANs);

		free(ve->RegistrationDenialBasis);
		free(ve->RestorationBasis);
		free(ve->RemovalBasis);

		free(*entity);
		*entity = NULL;
	}
}
