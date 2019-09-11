/**
 * Copyright 2015-2019 NETCAT (www.netcat.pl)
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
 * @copyright 2015-2019 NETCAT (www.netcat.pl)
 * @license http://www.apache.org/licenses/LICENSE-2.0
 */

#include "internal.h"
#include "nip24.h"

NIP24_API BOOL ibanstatus_new(IBANStatus** iban)
{
	IBANStatus* is = NULL;

	BOOL ret = FALSE;

	if ((is = (IBANStatus*)malloc(sizeof(IBANStatus))) == NULL) {
		goto err;
	}

	memset(is, 0, sizeof(IBANStatus));

	// ok
	*iban = is;
	is = NULL;

	ret = TRUE;

err:
	ibanstatus_free(&is);

	return ret;
}

NIP24_API void ibanstatus_free(IBANStatus** iban)
{
	IBANStatus* is = (iban ? *iban : NULL);

	if (is) {
		free(is->UID);

		free(is->NIP);
		free(is->REGON);
		free(is->IBAN);

		free(is->ID);
		free(is->Source);

		free(*iban);
		*iban = NULL;
	}
}
