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


NIP24_API BOOL wlstatus_new(WLStatus** wl)
{
	WLStatus* w = NULL;

	BOOL ret = FALSE;

	if ((w = (WLStatus*)malloc(sizeof(WLStatus))) == NULL) {
		goto err;
	}

	memset(w, 0, sizeof(WLStatus));

	// ok
	*wl = w;
	w = NULL;

	ret = TRUE;

err:
	wlstatus_free(&w);

	return ret;
}

NIP24_API void wlstatus_free(WLStatus** wl)
{
	WLStatus* w = (wl ? *wl : NULL);

	if (w) {
		free(w->UID);

		free(w->NIP);
		free(w->IBAN);
		free(w->Result);
		free(w->Source);

		free(*wl);
		*wl = NULL;
	}
}
