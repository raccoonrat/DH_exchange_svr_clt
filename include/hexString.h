#include <stdint.h>
#include <stdlib.h>
#include <string.h>

uint8_t
*hexStringToBytes(char *inhex);

char
*bytesToHexString(uint8_t *bytes, size_t buflen);
