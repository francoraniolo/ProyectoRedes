#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>

#include <ctype.h>
#include <errno.h>
#include <math.h>
#include <netdb.h>
#include <resolv.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

//#include "loc.h"

const char *precsize_ntoa();

/* takes an on-the-wire LOC RR and formats it in a human readable format. */
const char *
loc_ntoa(binary, ascii)
	const u_char *binary;
	char *ascii;
{
	static char *error = "?";
	static char tmpbuf[sizeof
"1000 60 60.000 N 1000 60 60.000 W -12345678.00m 90000000.00m 90000000.00m 90000000.00m"];
	const u_char *cp = binary;

	int latdeg, latmin, latsec, latsecfrac;
	int longdeg, longmin, longsec, longsecfrac;
	char northsouth, eastwest;
	int altmeters, altfrac, altsign;

	const u_int32_t referencealt = 100000 * 100;

	int32_t latval, longval, altval;
	u_int32_t templ;
	u_int8_t sizeval, hpval, vpval, versionval;
    
	char *sizestr, *hpstr, *vpstr;

	versionval = *cp++;

	if (ascii == NULL)
		ascii = tmpbuf;

	if (versionval) {
		(void) sprintf(ascii, "; error: unknown LOC RR version");
		return (ascii);
	}

	sizeval = *cp++;

	hpval = *cp++;
	vpval = *cp++;

	GETLONG(templ, cp);
	latval = (templ - ((unsigned)1<<31));

	GETLONG(templ, cp);
	longval = (templ - ((unsigned)1<<31));

	GETLONG(templ, cp);
	if (templ < referencealt) { /* below WGS 84 spheroid */
		altval = referencealt - templ;
		altsign = -1;
	} else {
		altval = templ - referencealt;
		altsign = 1;
	}

	if (latval < 0) {
		northsouth = 'S';
		latval = -latval;
	} else
		northsouth = 'N';

	latsecfrac = latval % 1000;
	latval = latval / 1000;
	latsec = latval % 60;
	latval = latval / 60;
	latmin = latval % 60;
	latval = latval / 60;
	latdeg = latval;

	if (longval < 0) {
		eastwest = 'W';
		longval = -longval;
	} else
		eastwest = 'E';

	longsecfrac = longval % 1000;
	longval = longval / 1000;
	longsec = longval % 60;
	longval = longval / 60;
	longmin = longval % 60;
	longval = longval / 60;
	longdeg = longval;

	altfrac = altval % 100;
	altmeters = (altval / 100) * altsign;

	if ((sizestr = strdup(precsize_ntoa(sizeval))) == NULL)
		sizestr = error;
	if ((hpstr = strdup(precsize_ntoa(hpval))) == NULL)
		hpstr = error;
	if ((vpstr = strdup(precsize_ntoa(vpval))) == NULL)
		vpstr = error;

	sprintf(ascii,
	      "%d %.2d %.2d.%.3d %c %d %.2d %.2d.%.3d %c %d.%.2dm %sm %sm %sm",
		latdeg, latmin, latsec, latsecfrac, northsouth,
		longdeg, longmin, longsec, longsecfrac, eastwest,
		altmeters, altfrac, sizestr, hpstr, vpstr);

	if (sizestr != error)
		free(sizestr);
	if (hpstr != error)
		free(hpstr);
	if (vpstr != error)
		free(vpstr);

	return (ascii);
}

static unsigned int poweroften[10] = {1, 10, 100, 1000, 10000, 100000,
				      1000000,10000000,100000000,1000000000};

/* takes an XeY precision/size value, returns a string representation. */
const char *
precsize_ntoa(prec)
	u_int8_t prec;
{
	static char retbuf[sizeof "90000000.00"];	/* XXX nonreentrant */
	unsigned long val;
	int mantissa, exponent;

	mantissa = (int)((prec >> 4) & 0x0f) % 10;
	exponent = (int)((prec >> 0) & 0x0f) % 10;

	val = mantissa * poweroften[exponent];

	(void) sprintf(retbuf, "%ld.%.2ld", val/100, val%100);
	return (retbuf);
}
