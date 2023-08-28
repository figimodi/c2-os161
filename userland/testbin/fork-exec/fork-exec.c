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
#include <unistd.h>
#include <err.h>
#include <string.h>

int
main(void)
{	
	printf("**************fork-exec**************\n");

	printf("Will fork, parent will wait, child will exec add\n");

	__pid_t c_pid = fork();
	int ret, stat;

	if(c_pid){
		/* Parent process */
		ret = waitpid(c_pid, &stat, 0);
		if(ret == -1){
			printf("Waitpid failed\n");
		}else{
			printf("Child process exited with code %d\n", stat);
		}
	}else{
		/* Child process */
		printf("Will call exec with parameters 1 and 2\n");
		char *args[4];
		char arg0[10];
		char arg1[10];
		char arg2[10];
		args[0] = arg0;
		args[1] = arg1;
		args[2] = arg2;
		args[3] = NULL;
		strcpy(args[0], "add");
		strcpy(args[1], "1");
		strcpy(args[2], "2");
		printf("Moving to add program...\n");
		ret = execv("testbin/add", args);

		printf("Execv returned, big error --> %d\n", ret);
	}
	return 0;
}
