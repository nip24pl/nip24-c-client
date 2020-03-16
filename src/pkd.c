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

#include "internal.h"
#include "nip24.h"


NIP24_API BOOL pkd_new(PKD** pkd)
{
	PKD* p = NULL;

	BOOL ret = FALSE;

	if ((p = (PKD*)malloc(sizeof(PKD))) == NULL) {
		goto err;
	}

	memset(p, 0, sizeof(PKD));

	// ok
	*pkd = p;
	p = NULL;

	ret = TRUE;

err:
	pkd_free(&p);

	return ret;
}

NIP24_API void pkd_free(PKD** pkd)
{
	PKD* p = (pkd ? *pkd : NULL);

	if (p) {
		free(p->Code);
		free(p->Description);

		free(*pkd);
		*pkd = NULL;
	}
}
