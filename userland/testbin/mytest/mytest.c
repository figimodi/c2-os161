/*
 * Copyright (c) 2000, 2001, 2002, 2003, 2004, 2005, 2008, 2009
 *	The President and Fellows of Harvard College.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE UNIVERSITY AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE UNIVERSITY OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * Simple program to add two numbers (given in as arguments). Used to
 * test argument passing to child processePs.
 *
 * Intended for the basic system calls assignment; this should work
 * once execv() argument handling is implemented.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <err.h>
#include <kern/seek.h>
#include <kern/fcntl.h>

int
// main(int argc, char *argv[])
// {	
main()
{	

	// printf("argc: %d\n", argc);
	// printf("argv: %x\n", (int)argv);

	// char * add = (char *)0x7ffffffc;
	// printf("%s\n", add);
	// printf("argv[0]: %s\n", argv[0]);
	// return 0;

	printf("*******************TEST FILE*******************\n\n");
	char buffer[128];
	int fd, result;
	fd = open("fileprova", O_WRONLY, NULL);
	printf("trying to read a WRITEONLY file...\n");
	result = read(fd, buffer, 128);
	if(result)
		printf("I tried to read, and i read %s\n", buffer);
	else
		printf("I couldn't read a WRITEONLY file\n");
	close(fd);

	fd = open("fileprova", O_RDONLY, NULL);
	printf("trying to write a READONLY file...\n");
	strcpy(buffer, "adding stuff\n");
	result = write(fd, buffer, 128);
	if(result)
		printf("I tried to wrote, and i wrote %s\n", buffer);
	else
		printf("I couldn't wrote a READONLY file\n");
	close(fd);

	fd = open("fileprova", O_RDWR | O_APPEND, NULL);
	read(fd, buffer, 128);
	printf("trying to append into this file:\n%s\n", buffer);
	strcpy(buffer, "appending stuff\n");
	result = write(fd, buffer, 128);
	if(result)
	{
		read(fd, buffer, 128);
		printf("I tried to append, now the file is:\n%s\n", buffer);
	}
	else
		printf("I couldn't wrote a READONLY file\n");
	close(fd);
}
