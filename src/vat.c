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


NIP24_API BOOL vatstatus_new(VATStatus** vat)
{
	VATStatus* vs = NULL;

	BOOL ret = FALSE;

	if ((vs = (VATStatus*)malloc(sizeof(VATStatus))) == NULL) {
		goto err;
	}

	memset(vs, 0, sizeof(VATStatus));

	// ok
	*vat = vs;
	vs = NULL;

	ret = TRUE;

err:
	vatstatus_free(&vs);

	return ret;
}

NIP24_API void vatstatus_free(VATStatus** vat)
{
	VATStatus* vs = (vat ? *vat : NULL);

	if (vs) {
		free(vs->UID);

		free(vs->NIP);
		free(vs->REGON);
		free(vs->Name);

		free(vs->Result);

		free(vs->ID);
		free(vs->Source);

		free(*vat);
		*vat = NULL;
	}
}
