/**
 * Copyright 2015-2025 NETCAT (www.netcat.pl)
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
 * @copyright 2015-2025 NETCAT (www.netcat.pl)
 * @license http://www.apache.org/licenses/LICENSE-2.0
 */

#include "internal.h"
#include "nip24.h"


static const char* _nip24_codes[] = {
    /* NIP24_ERR_CLI_CONNECT */     "Nie udało się nawiązać połączenia z serwisem NIP24",
    /* NIP24_ERR_CLI_RESPONSE */    "Odpowiedź serwisu NIP24 ma nieprawidłowy format",
    /* NIP24_ERR_CLI_NUMBER */      "Nieprawidłowy typ numeru",
    /* NIP24_ERR_CLI_NIP */         "Numer NIP jest nieprawidłowy",
    /* NIP24_ERR_CLI_REGON */       "Numer REGON jest nieprawidłowy",
    /* NIP24_ERR_CLI_KRS */         "Numer KRS jest nieprawidłowy",
    /* NIP24_ERR_CLI_EUVAT */       "Numer EU VAT ID jest nieprawidłowy",
    /* NIP24_ERR_CLI_IBAN */        "Numer IBAN jest nieprawidłowy",
    /* NIP24_ERR_CLI_EXCEPTION */   "Funkcja wygenerowała wyjątek",
    /* NIP24_ERR_CLI_DATEFORMAT */  "Podana data ma nieprawidłowy format",
    /* NIP24_ERR_CLI_INPUT */       "Nieprawidłowy parametr wejściowy funkcji"
};

NIP24_API const char* nip24_errstr(int code)
{
    if (code < NIP24_ERR_CLI_CONNECT || code > NIP24_ERR_CLI_DATEFORMAT) {
        return NULL;
    }

    return _nip24_codes[code - NIP24_ERR_CLI_CONNECT];
}
