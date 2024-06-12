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

#include "internal.h"
#include "nip24.h"


NIP24_API BOOL businesspartner_new(BusinessPartner** bp)
{
	BusinessPartner* p = NULL;

	BOOL ret = FALSE;

	if ((p = (BusinessPartner*)malloc(sizeof(BusinessPartner))) == NULL) {
		goto err;
	}

	memset(p, 0, sizeof(BusinessPartner));

	// ok
	*bp = p;
	p = NULL;

	ret = TRUE;

err:
	businesspartner_free(&p);

	return ret;
}

NIP24_API void businesspartner_free(BusinessPartner** bp)
{
	BusinessPartner* p = (bp ? *bp : NULL);

	if (p) {
		free(p->REGON);
		free(p->FirmName);
		free(p->FirstName);
		free(p->SecondName);
		free(p->LastName);

		free(*bp);
		*bp = NULL;
	}
}
