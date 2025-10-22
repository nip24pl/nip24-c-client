# NIP24 Client for C/C++

This is the official repository for [NIP24](https://nip24.pl) Client for C/C++

This library contains validators for common Polish tax numbers like NIP, REGON and KRS. Validators for EU VAT ID
and IBAN are also included. After registration at [NIP24](https://nip24.pl) Portal this library could be used for
various on-line validations of Polish and EU companies. Please, visit our web page for more details.

## Documentation

The documentation and samples are available [here](https://nip24.pl/dokumentacja/).

## Build

Microsoft Visual Studio 2022 is required to build this library. Simply open the solution file (nip24Library.sln) in the
IDE and build the _Release_ version. You can also build it from the _Developer Command Prompt for Visual Studio_:

```bash
git clone https://github.com/nip24pl/nip24-c-client.git
cd nip24-c-client

msbuild nip24Library.sln /t:Rebuild /p:Configuration=Release /p:Platform=x86
msbuild nip24Library.sln /t:Rebuild /p:Configuration=Release /p:Platform=x64
```

## How to use

All required header files are in _nip24-c-client/include_. Add this path to your project's include directories.
Then include _nip24.h_ in your source code — it provides all API definitions.

```bash
#include "nip24.h"
```

The compiled and built libraries are located in two separate directories:
* _nip24-c-client/lib_ - contains the library built for 32-bit architecture (x86),
* _nip24-c-client/lib64_ - contains the library built for 64-bit architecture (x64).

## License

This project is delivered under Apache License, Version 2.0:

- [![License (Apache 2.0)](https://img.shields.io/badge/license-Apache%20version%202.0-blue.svg?style=flat-square)](http://www.apache.org/licenses/LICENSE-2.0)