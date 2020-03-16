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

#ifndef __NIP24_API_H__
#define __NIP24_API_H__

/////////////////////////////////////////////////////////////////

#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <stdio.h>
#include <time.h>

/////////////////////////////////////////////////////////////////

#ifdef NIP24_STATIC
	#define NIP24_API
#else
	#ifdef NIP24_EXPORTS
		#define NIP24_API __declspec(dllexport)
	#else
		#define NIP24_API __declspec(dllimport)
	#endif
#endif

/////////////////////////////////////////////////////////////////

#include "nip24_error.h"
#include "nip24_validate.h"
#include "nip24_invoice.h"
#include "nip24_pkd.h"
#include "nip24_all.h"
#include "nip24_vies.h"
#include "nip24_vat.h"
#include "nip24_iban.h"
#include "nip24_wl.h"
#include "nip24_vatentity.h"
#include "nip24_search.h"
#include "nip24_account.h"
#include "nip24_client.h"

/////////////////////////////////////////////////////////////////

#endif
