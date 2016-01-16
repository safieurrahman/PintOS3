#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"

static void syscall_handler (struct intr_frame *);
struct list process_info_list;
static struct lock pil_lock;
static struct lock file_lock;
static struct lock multi_lock;
static struct file *file_fd[128];

static int counter = 0;
static int fd = 3;
static int fdarr[128];

bool check_ptr(void* ptr) {
  struct thread* t = thread_current();
  if ( !is_user_vaddr (ptr) || pagedir_get_page(t->pagedir, ptr) == NULL) {
    return false;
  }
  return true;
}

struct process_info* get_process_info(tid_t pid) {
  struct list_elem *e;
  //printf("looking for pid=%d\n", pid);

  struct process_info* pi = NULL;
  lock_acquire(&pil_lock);
  for (e = list_begin (&process_info_list); e != list_end (&process_info_list);
       e = list_next (e))
  {
      struct process_info *p = list_entry (e, struct process_info, elem);
      if (p->pid == pid) {
        //printf("getting pid=%d, exit=%d\n", pid, p->exit_code);
        pi = p;
        break;
      }
  }

  lock_release(&pil_lock);

  return pi;
}


void add_process_to_list(const char* name, tid_t tid) {
  struct process_info *pi  = (struct process_info*) malloc (sizeof(struct process_info));
  pi->exit_code = -1000;
  pi->pid = tid;
  sema_init(&pi->intazar,1);
 
  memcpy(pi->name, name, strlen(name)+1);

  lock_acquire(&pil_lock);
  list_push_back(&process_info_list, &pi->elem);
  lock_release(&pil_lock);
}

void set_process_exitcode(tid_t pid, int exit_code) {
  struct list_elem *e;

  lock_acquire(&pil_lock);

  for (e = list_begin (&process_info_list); e != list_end (&process_info_list);
       e = list_next (e))
    {
      struct process_info *p = list_entry (e, struct process_info, elem);
      if (p->pid == pid) {
        p->exit_code = exit_code;
        break;
      }
    }

  lock_release(&pil_lock);
}



void create(struct intr_frame *f, int* esp) {
  if ( !check_ptr(esp+1) || !check_ptr(esp+2) ) {
    exit(-1);
    return;
  }
  if (!check_ptr((void*)(*(esp + 1))) ){
    exit(-1);
    return;
  }

  char* buffer = *(esp + 1);
  unsigned int size = *(esp + 2);
  if (strlen(buffer) == 0) {
    f->eax = 0;
    return;
  }
  else {
	//lock_acquire(&file_lock);
        f->eax = filesys_create(buffer, size);
	//lock_release(&file_lock);
  }
}

void remove(struct intr_frame *f, int* esp) {
char* buffer = *(esp + 1);  
if ( !check_ptr(esp+1) ){
    exit(-1);
    return;
  }
  if (!check_ptr((void*)(*(esp + 1))) ){
    exit(-1);
    return;
  }
	lock_acquire(&file_lock);
    	f->eax = filesys_remove(buffer);
	lock_release(&file_lock);
  
}

void open(struct intr_frame *f, int* esp) {
  if ( !check_ptr(esp+1)  ) {
    exit(-1);
    return;
  }
  if (!check_ptr((void*)*(esp + 1)) ){
    exit(-1);
    return;
  }

  char* buffer = (void*)*(esp + 1);
  if (strlen(buffer) == 0) {
    f->eax = -1;
    return;
  }
  else {
  lock_acquire(&file_lock);
  struct file *fopen = filesys_open(buffer);
 if (strstr(buffer, get_process_info(thread_current()->tid)->name)!=NULL)
{
file_deny_write(fopen);
}
  if(!fopen)
  {
	lock_release(&file_lock);
     f->eax = -1;
     return;
  }
else {


	file_fd[counter] = fopen;
	fd = fd + 1;
	fdarr[counter] = fd;
	counter++;
	f->eax = fd;
	lock_release(&file_lock);
}
 
  }
}



void exit(int exit_code) {
  set_process_exitcode(thread_current()->tid, exit_code);
  struct process_info* pi = get_process_info(thread_current()->tid) ;

  printf("%s: exit(%d)\n", pi->name , exit_code);
  thread_exit();
} 
	

void write(struct intr_frame *f, int* esp) {
  if ( !check_ptr(esp+1) || !check_ptr(esp+2) || !check_ptr(esp+3) ) {
    exit(-1);
    return;
  }
  
  int fd = *(esp + 1);
  void* buffer = *(esp + 2);
  unsigned int len = *(esp + 3);

  if (!check_ptr( buffer )){
    exit(-1);
    return;
  }

  if (fd == STDIN_FILENO) {
    exit(-1);
    return;
  }
  else if (fd == STDOUT_FILENO) {
    putbuf(buffer, len);
    f->eax = len;
  }
  else {
	struct file *fwrite=NULL;
	    int i;
	    for(i=0;i<128;i++)
	    {
		 
		
		if (fd == fdarr[i])
		{
			fwrite = file_fd[i];
			
			if(!fwrite){
				f->eax = 0;			
				return;		
			}
			
			else {
				lock_acquire(&file_lock);
				f->eax = file_write(fwrite,buffer,len);
				lock_release(&file_lock);				
				return;
			}	
      	        }
            }
	

}
}
void read(struct intr_frame *f, int* esp) {
  if ( !check_ptr(esp+1) || !check_ptr(esp+2) || !check_ptr(esp+3) ) {
    exit(-1);
    return;
  }

  int fd = *(esp + 1);
  void* buffer = *(esp + 2);
  unsigned int len = *(esp + 3);

  if (!check_ptr( buffer )){
    exit(-1);
    return;
  }

  if (fd == STDIN_FILENO) {
  }
  else if (fd == STDOUT_FILENO) {
    exit(-1);
    return;
  }
  else {
	struct file *fread=NULL;
	    int i;
	    for(i=0;i<128;i++)
            {
		 
		
		if (fd == fdarr[i])
		{
			fread = file_fd[i];
			
			if(!fread)
			{
				f->eax = 0;
				exit(0);			
				return;		
			}
			
			else {
				lock_acquire(&file_lock);
				f->eax = file_read(fread,buffer,len);
				lock_release(&file_lock);				
				return;
			}	
      	        }
           }
      }
}
void filesize(struct intr_frame *f, int* esp) {

int size=-1;
int i=0;
struct file *fsize=NULL;
	for (i=0; i < 128 ; i++)
	{
		if (fd == fdarr[i])
		{
			//lock_acquire(&file_lock);
			fsize= file_fd[i];
			if (!fsize)
			{
			//lock_release(&file_lock);
			f->eax=-1; 	
			exit(-1);
			return;
			}
			else
			{
   				size = file_length(fsize);
				//lock_release(&file_lock);
				
				
			}
		}
	}
f->eax = size;

  
}

void 
exec(struct intr_frame *f, int* esp) {
  if ( !check_ptr(esp+1) ) {
    exit(-1);
    return;
  }
  if (!check_ptr((void*)(*(esp + 1))) ){
    f->eax = -1;
    exit(-1);
  }
  
  char *name = *(esp + 1);
  
  if (strlen(name) == 0) {
    f->eax = -1;
    return;
  }


	//sema_down(&get_process_info(thread_current()->tid)->intazar);


 //lock_acquire(&multi_lock);
  int r=process_execute(name);
	//if(r == TID_ERROR) {
	//f->eax=-1;
	//return;
//}


  f->eax = r;
	//lock_release(&multi_lock);
//lock_release(&file_lock);
}
void 
wait(struct intr_frame *f, int* esp) {
tid_t tid;
  
if ( !check_ptr(esp+1)) 
  {
    exit(-1);
    return;
  }

  //lock_acquire(&multi_lock);
  tid = *(esp + 1);
	/*if (!tid)
	{
	lock_release(&multi_lock);
	f->eax=-1;
	exit(-1);
	return;
	}
   */
    f->eax = process_wait(tid);
   // lock_release(&multi_lock);
  
}
void 
seek (struct intr_frame *f, int* esp)
{

  if ( !check_ptr(esp+1) || !check_ptr(esp+2) ) {
    exit(-1);
    return;
  }
  
  int fd = *(esp + 1);
  unsigned int position = *(esp + 2);
  int i=0;
  struct file *fseek=NULL;
	for (i=0; i < 128 ; i++)
	{
		if (fd == fdarr[i])
		{
			//lock_acquire(&file_lock);
			fseek= file_fd[i];
			if (!fseek)
			{
			//lock_release(&file_lock);
			f->eax=-1; 	
			exit(-1);
			return;
			}
			else
			{
   		        f->eax = file_seek(fseek, position);
  			//lock_release(&file_lock);
				
				
			}
		}
	}
 
}
void 
tell (struct intr_frame *f, int* esp)
{
  if ( !check_ptr(esp+1) || !check_ptr(esp+2) ) {
    exit(-1);
    return;
  }
  
  int fd = *(esp + 1);
  int i=0;
  struct file *ftell=NULL;
	for (i=0; i < 128 ; i++)
	{
		if (fd == fdarr[i])
		{
			//lock_acquire(&file_lock);
			ftell= file_fd[i];
			if (!ftell)
			{
			//lock_release(&file_lock);
			f->eax=-1; 	
			exit(-1);
			return;
			}
			else
			{
   			f->eax = file_tell(ftell);
  			//lock_release(&file_lock);
				
				
			}
		}
	}
}
void 
close (struct intr_frame *f, int* esp)
{
  if ( !check_ptr(esp+1)) {
    exit(-1);
    return;
  }
 // void* a=0;
  int fd = *(esp + 1);
  int i=0;
  struct file *fclose=NULL;
	for (i=0; i < 128 ; i++)
	{
		if (fd == fdarr[i])
		{
			lock_acquire(&file_lock);
			fclose= file_fd[i];
			if (!fclose || fclose==NULL)
			{
			lock_release(&file_lock);
			f->eax=-1; 	
			exit(-1);
			return;
			}
			else
			{
			f->eax = file_close(fclose);
				//fclose=NULL;
file_fd[i]=NULL;
  			lock_release(&file_lock);
			
			
			}
			break;
		}

	}
}
void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  list_init(&process_info_list);
  lock_init(&pil_lock);
  lock_init(&file_lock);
lock_init(&multi_lock);
}


static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  int* esp = f->esp;
  
  if ( !check_ptr(esp)) {
    exit(-1);
    return;
  }

  int number = *esp;
  if (number == 0) {
    shutdown_power_off();
  }
  else if (number == 1) {
    if ( !check_ptr(esp+1) ) {
      exit(-1);
      return;
    }
    int exit_code = *(esp+1) ;
    exit(exit_code);
  }
 
  else if (number == SYS_CREATE) {
    create(f, esp);
  }
  else if (number == SYS_REMOVE) {
    remove(f, esp);
  }
  else if (number == SYS_OPEN) {
    open(f,esp);
  }
  else if (number == SYS_WRITE) {
    write(f, esp);
  }
  else if (number == SYS_READ) {
    read(f, esp);
  }
   else if (number == SYS_EXEC) {
   exec(f,esp);
  }
  else if (number == SYS_WAIT) {
    wait(f, esp);
  }
  else if (number == SYS_FILESIZE) {
    filesize(f, esp);
  }
 else if (number == SYS_SEEK) {
    seek(f, esp);
  }
 else if (number == SYS_TELL) {
    tell(f, esp);
  }
 else if (number == SYS_CLOSE) {
    close(f, esp);
  }

}



