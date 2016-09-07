/*
 * Copyright (c) 2006 Bob Beck <beck@openbsd.org>
 * Copyright (c) 2002-2006 Henning Brauer <henning@openbsd.org>
 * Copyright (c) 2001 Markus Friedl.  All rights reserved.
 * Copyright (c) 2001 Daniel Hartmeier.  All rights reserved.
 * Copyright (c) 2001 Theo de Raadt.  All rights reserved.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

%{
#include <errno.h>
#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "synk.h"

static TAILQ_HEAD(files, file) files = TAILQ_HEAD_INITIALIZER(files);
static struct file {
	TAILQ_ENTRY(file) entry;
	FILE *stream;
	char *name;
	int lineno;
	int errors;
} *file, *topfile;

static struct file *pushfile(const char *);
static int popfile(void);
static int yyparse(void);
static int yylex(void);
static int yyerror(const char *, ...);
static int kwcmp(const void *, const void *);
static int lookup(char *);
static int lgetc(int);
static int lungetc(int);
static int findeol(void);

static struct peers_t *peers = NULL;

typedef struct {
	union {
		int number;
		char *string;
	} v;
	int lineno;
} YYSTYPE;
%}

%token PEER ERROR
%token <v.string> STRING
%token <v.number> NUMBER
%%

grammar		: /* empty */
		| grammar '\n'
		| grammar main '\n'
		| grammar error '\n' {
			file->errors++;
		}
		;

main		: PEER STRING NUMBER {
			addpeer(peers, $2, $3);
		}
		| PEER STRING {
			addpeer(peers, $2, DEFPORT);
		}
		;
%%

struct keywords {
	const char *name;
	int val;
};

static int
yyerror(const char *fmt, ...)
{
	char buf[512];
	va_list ap;

	file->errors++;
	va_start(ap, fmt);
	if (vsnprintf(buf, sizeof(buf), fmt, ap) < 0)
		perror("vsnprintf");
	va_end(ap);
	fprintf(stderr, "%s:%d: %s\n", file->name, yylval.lineno, buf);
	return 0;
}

static int
kwcmp(const void *k, const void *e)
{
	return strcmp(k, ((const struct keywords *)e)->name);
}

static int
lookup(char *s)
{
	/* this has to be sorted always */
	static const struct keywords keywords[] = {
		{ "peer", PEER }
	};
	const struct keywords *p;

	p = bsearch(s, keywords, sizeof(keywords)/sizeof(keywords[0]),
	            sizeof(keywords[0]), kwcmp);

	if (p)
		return p->val;
	else
		return STRING;
}

#define MAXPUSHBACK 128

static unsigned char *parsebuf;
static int parseindex;
static unsigned char pushback_buffer[MAXPUSHBACK];
static int pushback_index = 0;

static int
lgetc(int quotec)
{
	int c, next;

	if (parsebuf) {
		/* Read character from the parsebuffer instead of input. */
		if (parseindex >= 0) {
			c = parsebuf[parseindex++];
			if (c != '\0')
				return c;
			parsebuf = NULL;
		} else
			parseindex++;
	}

	if (pushback_index)
		return pushback_buffer[--pushback_index];

	if (quotec) {
		if ((c = getc(file->stream)) == EOF) {
			yyerror("reached end of file while parsing "
			    "quoted string");
			if (file == topfile || popfile() == EOF)
				return EOF;
			return quotec;
		}
		return c;
	}

	while ((c = getc(file->stream)) == '\\') {
		next = getc(file->stream);
		if (next != '\n') {
			c = next;
			break;
		}
		yylval.lineno = file->lineno;
		file->lineno++;
	}

	while (c == EOF) {
		if (file == topfile || popfile() == EOF)
			return EOF;
		c = getc(file->stream);
	}
	return c;
}

static int
lungetc(int c)
{
	if (c == EOF)
		return EOF;
	if (parsebuf) {
		parseindex--;
		if (parseindex >= 0)
			return c;
	}
	if (pushback_index < MAXPUSHBACK-1)
		return pushback_buffer[pushback_index++] = c;
	else
		return EOF;
}

static int
findeol(void)
{
	int c;

	parsebuf = NULL;
	pushback_index = 0;

	/* skip to either EOF or the first real EOL */
	while (1) {
		c = lgetc(0);
		if (c == '\n') {
			file->lineno++;
			break;
		}
		if (c == EOF)
			break;
	}
	return ERROR;
}

static int
yylex(void)
{
	unsigned char buf[8096];
	unsigned char *p;
	int quotec, next, c;
	int token;

	p = buf;
	while ((c = lgetc(0)) == ' ' || c == '\t')
		; /* nothing */

	yylval.lineno = file->lineno;
	if (c == '#')
		while ((c = lgetc(0)) != '\n' && c != EOF)
			; /* nothing */

	switch (c) {
	case '\'':
	case '"':
		quotec = c;
		while (1) {
			if ((c = lgetc(quotec)) == EOF)
				return 0;
			if (c == '\n') {
				file->lineno++;
				continue;
			} else if (c == '\\') {
				if ((next = lgetc(quotec)) == EOF)
					return 0;
				if (next == quotec || c == ' ' || c == '\t')
					c = next;
				else if (next == '\n')
					continue;
				else
					lungetc(next);
			} else if (c == quotec) {
				*p = '\0';
				break;
			} else if (c == '\0') {
				yyerror("syntax error");
				return findeol();
			}
			if (p + 1 >= buf + sizeof(buf) - 1) {
				yyerror("string too long");
				return findeol();
			}
			*p++ = c;
		}
		yylval.v.string = strdup((char *)buf);
		if (!yylval.v.string)
			perror("strdup");
		return STRING;
	}

#define allowed_to_end_number(x) \
	(isspace(x) || x == ')' || x ==',' || x == '/' || x == '}' || x == '=')

	if (c == '-' || isdigit(c)) {
		do {
			*p++ = c;
			if ((unsigned)(p-buf) >= sizeof(buf)) {
				yyerror("string too long");
				return findeol();
			}
		} while ((c = lgetc(0)) != EOF && isdigit(c));
		lungetc(c);
		if (p == buf + 1 && buf[0] == '-')
			goto nodigits;
		if (c == EOF || allowed_to_end_number(c)) {

			*p = '\0';
			yylval.v.number = strtoll((char *)buf, NULL, 10);
			if (errno == ERANGE) {
				yyerror("\"%s\" invalid number: %s",
				    buf, strerror(errno));
				return findeol();
			}
			return NUMBER;
		} else {
nodigits:
			while (p > buf + 1)
				lungetc(*--p);
			c = *--p;
			if (c == '-')
				return c;
		}
	}

#define allowed_in_string(x) \
	(isalnum(x) || (ispunct(x) && x != '(' && x != ')' && \
	x != '{' && x != '}' && x != '<' && x != '>' && \
	x != '!' && x != '=' && x != '/' && x != '#' && \
	x != ','))

	if (isalnum(c) || c == ':' || c == '_' || c == '*') {
		do {
			*p++ = c;
			if ((unsigned)(p-buf) >= sizeof(buf)) {
				yyerror("string too long");
				return findeol();
			}
		} while ((c = lgetc(0)) != EOF && (allowed_in_string(c)));
		lungetc(c);
		*p = '\0';
		if ((token = lookup((char *)buf)) == STRING)
			if (!(yylval.v.string = strdup((char *)buf)))
				perror("strdup");
		return token;
	}
	if (c == '\n') {
		yylval.lineno = file->lineno;
		file->lineno++;
	}
	if (c == EOF)
		return 0;
	return c;
}

static struct file *
pushfile(const char *name)
{
	struct file *nfile;

	if (!(nfile = calloc(1, sizeof(struct file))))
		return NULL;
	if (!(nfile->name = strdup(name))) {
		free(nfile);
		return NULL;
	}
	if (!(nfile->stream = fopen(nfile->name, "r"))) {
		free(nfile->name);
		free(nfile);
		return NULL;
	}
	nfile->lineno = 1;
	TAILQ_INSERT_TAIL(&files, nfile, entry);
	return nfile;
}

static int
popfile(void)
{
	struct file *prev;

	if ((prev = TAILQ_PREV(file, files, entry)))
		prev->errors += file->errors;
	TAILQ_REMOVE(&files, file, entry);
	fclose(file->stream);
	free(file->name);
	free(file);
	file = prev;
	return file ? 0 : EOF;
}

int
parseconf(struct peers_t *plist, const char *filename)
{
	int errors = 0;

	if (!(file = pushfile(filename))) {
		fprintf(stderr, "failed to open %s\n", filename);
		return -1;
	}
	topfile = file;

	peers = plist;

	yyparse();
	errors = file->errors;
	popfile();

	if (errors != 0)
		return -1;

	return errors != 0 ? -1 : 0;
}
