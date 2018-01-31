#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*

Utilities

*/


char *substr(char *src, int pos, int len) {
	char *dest = NULL;
	if (len>0) {
		dest = calloc(len + 1, 1);
		if (NULL != dest) {
			strncat(dest, src + pos, len);
		}
	}
	return dest;
}