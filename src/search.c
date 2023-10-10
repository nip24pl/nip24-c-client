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


NIP24_API BOOL searchresult_new(SearchResult** result)
{
	SearchResult* sr = NULL;

	BOOL ret = FALSE;

	if ((sr = (SearchResult*)malloc(sizeof(SearchResult))) == NULL) {
		goto err;
	}

	memset(sr, 0, sizeof(SearchResult));

	// ok
	*result = sr;
	sr = NULL;

	ret = TRUE;

err:
	searchresult_free(&sr);

	return ret;
}

NIP24_API void searchresult_free(SearchResult** result)
{
	SearchResult* sr = (result ? *result : NULL);

	int i;

	if (sr) {
		free(sr->UID);
		free(sr->ID);

		for (i = 0; i < sr->ResultsCount; i++) {
			if (sr->ResultsType == NIP24_RESULT_VAT_ENTITY) {
				vatentity_free(&sr->Results.VATEntity[i]);
			}
		}

		free(sr->Results.VATEntity);
		free(sr->Source);

		free(*result);
		*result = NULL;
	}
}
