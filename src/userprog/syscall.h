#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include "threads/interrupt.h"

void syscall_init (void);
void syscall_simple_exit (struct intr_frame *, int);

#endif /* userprog/syscall.h */
