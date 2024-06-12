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


NIP24_API BOOL invoicedata_new(InvoiceData** invoice)
{
	InvoiceData* id = NULL;

	BOOL ret = FALSE;

	if ((id = (InvoiceData*)malloc(sizeof(InvoiceData))) == NULL) {
		goto err;
	}

	memset(id, 0, sizeof(InvoiceData));

	// ok
	*invoice = id;
	id = NULL;

	ret = TRUE;

err:
	invoicedata_free(&id);

	return ret;
}

NIP24_API void invoicedata_free(InvoiceData** invoice)
{
	InvoiceData* id = (invoice ? *invoice : NULL);

	if (id) {
		free(id->UID);

		free(id->NIP);
		free(id->Name);
		free(id->FirstName);
		free(id->LastName);

		free(id->Street);
		free(id->StreetNumber);
		free(id->HouseNumber);
		free(id->City);
		free(id->PostCode);
		free(id->PostCity);

		free(id->Phone);
		free(id->Email);
		free(id->WWW);

		free(*invoice);
		*invoice = NULL;
	}
}
