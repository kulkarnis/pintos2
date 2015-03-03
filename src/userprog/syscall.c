#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <user/syscall.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

static void syscall_handler (struct intr_frame *);
struct lock file_lock; //lock for handing file sys

//File structre
struct file_struct
{
	struct file* file; //file pointer
	int file_desc;     //file discriptor
	struct list_elem elem;
};

struct file*
get_file_handle (int file_desc)
{
	//printf("file handle 1\n");
   struct list_elem *e = list_begin (&thread_current()->files_owned_list);
   struct list_elem *next;
   while (e != list_end (&thread_current()->files_owned_list))
   {

     struct file_struct *f = list_entry (e, struct file_struct,
                                          elem);
     next = list_next(e);
     if (file_desc == f->file_desc)
       {
       //	printf("file handle 2\n");
        return f->file;
       }
     e = next;
   }
   return NULL;

}


void
syscall_init (void) 
{
	//("System call init...\n");
	lock_init (&file_lock);
  	intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}


//shut down os
void
sys_halt (void)
{
	shutdown_power_off();
}

//exit current thread and releases any resources acquired by it
void
sys_exit (int status)
{

	//printf("In exit...\n");
	struct thread *current = thread_current();	
	//set exit code as status
	current->chp->status = status; 
	
	printf("%s: exit(%d)\n", current->name, status);
	thread_exit();	 

}

static pid_t
sys_exec (const char *input)
{
	//printf("Exec call..\n");
	pid_t pid = process_execute(input);
	
}

static int
sys_write (int file_desc, const void *buffer, unsigned size)
{
	//printf("write 1\n");
	if (file_desc == STDOUT_FILENO)
	 {
	 	int left = size;
	 	while (left > 128)
	 		 {
	 		 	putbuf (buffer, 128);
	 		 	buffer = (const char *)buffer + 128;
	 		 	left = left - 128;

	 		 }
	 	putbuf (buffer, left);
	 //	printf("bytes wrriten to buffer: %d\n",size );
	 	return size;
	 }

	 lock_acquire (&file_lock);
	 struct file *file_ptr = get_file_handle (file_desc);
	// printf("write 2\n");
	 //if lock doesn't acquired then return
	 if (!file_ptr)
	 	 {
	 	 	lock_release (&file_lock);
	 	 	return -1;
	 	 }
	// printf("write 3\n");	 
	 int bytes_wrriten = file_write (file_desc, buffer, size);
	// printf("Wrriten to file bytes:%d\n",bytes_wrriten );
	 lock_release (&file_lock);
	 return bytes_wrriten;	 
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
	//printf("System call handler...\n");
	//printf("%x\n", * ( int *) f->esp);
	int arg[3];  //maximum 3 args are required by a syscall

	//validates the pointer
	validate_ptr((const void *) f->esp);

	//switch for diff system calls
	switch(* ( int *) f->esp)
	{
		case SYS_HALT:
		 {
			sys_halt();
			break;
		 }
		case SYS_EXIT:
		 {
		 	get_arguments_from_stack(f, &arg[0], 1);
		 	sys_exit(arg[0]);
		 	break;
		 }
		case SYS_EXEC:
		 {
		 	get_arguments_from_stack(f, &arg[0], 1);
		 	f->eax = sys_exec ((const char*)arg[0]);
		 	break;
		 } 
		case SYS_WRITE:
		 {
		 	get_arguments_from_stack (f, &arg[0], 3);
		// 	printf("writing....\n");
		 	//allocate_buffer ((void *) arg[1], (unsigned) arg[2]);

		 	f->eax = sys_write ((int) arg[0], (const void*)arg[1],
		 						(unsigned) arg[2]);
		 	break;
		 } 

	}
  
}

//get arguments from stack
void
get_arguments_from_stack (struct intr_frame *f, int *arg, int n)
{
	int i;
	
	for(i = 0; i < n; ++i)
		 {

		 	int *ptr = (int *)f->esp + i + 1;
		 	
		 	validate_ptr((const void *)ptr);
		 	arg[i] = *ptr;
		 //	printf("Arg[%d] :%s\n",i, &arg[i] );
		 }
}



//Add child thread/process to child list and add details like pid, exit status
struct
child_process* add_child (int pid)
{
	struct child_process* chp = malloc(sizeof(struct child_process));
	chp->pid = pid;
	chp->load = NOT_LOADED;
	chp->wait = false;
	chp->exit = false;
	lock_init(&chp->wait_lock);
	list_push_back(&thread_current()->child_list, &chp->elem);
	return chp;
}
//Validates stack pointer
void
validate_ptr (const void *addr)
{
	if (!is_user_vaddr (addr))
	 {
		sys_exit(-1);
	 }
}


