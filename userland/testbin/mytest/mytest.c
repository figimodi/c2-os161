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

int
main(void)
{	
	int testfile, offset = -1, nread = 0;
	char buffer[128];
	char * retval;
	
	testfile = open("fileprova", O_RDONLY, 0644);

	printf("**************lseek TEST***************\n");

	nread = read(testfile, buffer, 5);

	printf("Read %d bytes--->%s\n", nread, buffer);

	printf("Skipping 2 chars...\n");

	offset = lseek(testfile, 2, SEEK_CUR);
	printf("Offset is now %d\n", offset);

	read(testfile, buffer, 5);
	printf("Read %d bytes--->%s\n", nread, buffer);

	printf("**************dup2 TEST***************\n");
	lseek(testfile, 0, SEEK_SET);
	int newfd = 10;
	newfd = dup2(testfile, newfd);

	if(newfd == 10){
		printf("dup2 worked, the new fd is: %d\n", newfd);
	}else{
		printf("dup2 did not work, the returned value is: %d\n", newfd);
	}

	read(newfd, buffer, 5);
	printf("Read %d bytes--->%s\n", nread, buffer);

	close(testfile);
	close(newfd);

	printf("**************getcwd TEST***************\n");

	printf("The addres of the buffer is-->%d\n", (int)&buffer);
	retval = (char*)getcwd(buffer, 128);
	printf("retval is --> %s\n", retval);
	printf("The dir is --> %s\n", buffer);
	return 0;
}
