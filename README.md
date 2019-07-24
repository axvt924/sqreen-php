# sqreen-php

This is a PHP extension used for block SQLi from GET, POST, COOKIE params.

The extension will read automatically the input and try to find SQLi thanks to the libinjection library.

If a SQLi is found the request will be automatically blocked.
