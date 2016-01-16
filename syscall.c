#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include "filesys/filesys.h"
#include "filesys/file.h"


static void syscall_handler (struct intr_frame *);

struct list process_info_list;
static struct lock pil_lock;
static struct lock proc_lock;
static struct lock file_lock;
static int fd = 3;

int fd_array[135];
struct file *fd_file_ptrs[135];
int index=0;

bool check_ptr(void* ptr) {
  struct thread* t = thread_current();
  if ( !is_user_vaddr (ptr) || pagedir_get_page(t->pagedir, ptr) == NULL) {
    return false;
  }
  return true;
}

//////////////////////// GET FILE POINTER ////////////////////////
/*
* Checks the global array to find a valid fd (file descriptor)
* that matches the fd of the stack pointer. Then checks the 
* global array to find a file pointer corresponding to that array
*
*/////////////////////////////////////////////////////////////////  

struct file* getFilePtr(int fd){
  struct file *file=NULL;
  for(index=0;index<135;index++){
     if (fd == fd_array[index]){
	file = fd_file_ptrs[index];
	if(!file){
	   return NULL;				
	}else{
	   return file;	
	}					
     }//end if
  }//end for loop 
  return file;
}//end getFilePtrs

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

//Bonus code! System call handler for the create() system call.
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
    f->eax = filesys_create(buffer, size);
  }
}


//////////////////////////// OPEN \\\\\\\\\\\\\\\\\\\\\\\/
void open (struct intr_frame *f, int* esp) {
  if ( !check_ptr(esp+1)) {
    exit(-1);
    return;
  }
  if (!check_ptr((void*)(*(esp + 1))) ){
    exit(-1);
    return;
  }

  char* buffer = (void*)*(esp + 1);
 
  if (strlen(buffer) == 0) {
    f->eax = -1;
    return ;
  }
  else {
    struct file *file = filesys_open(buffer);

    if(!file){
      f->eax = -1;
  	return;
    }
   
   fd_array[fd] = fd; //storing fd in an array
   fd_file_ptrs[fd] = file;
   f->eax = fd;
   fd++;
  	 
  }
}
//////////////////////////// READ \\\\\\\\\\\\\\\\\\\\\\\/

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
	unsigned i;
    	for(i = 0; i < len; i++){
		char * c_ptr = (char *) buffer;
        	*(c_ptr+i) = input_getc ();
    }
    f->eax = len;
    return;
   
  }

  else if (fd == STDOUT_FILENO) {
     exit(-1);
     return;
  }

  else {
    struct file *file=NULL;
    file = getFilePtr(fd);
    if(file){
        lock_acquire(&file_lock);
	f->eax = file_read (file, buffer, len) ;
	lock_release(&file_lock);
    }else{
	f->eax = -1;
    }
  }
}


//////////////////////////// WRITE \\\\\\\\\\\\\\\\\\\\\\\/

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
    struct file *file=NULL;
    file = getFilePtr(fd);
    if(file){
        lock_acquire(&file_lock);
	f->eax = file_write (file, buffer, len) ;
	lock_release(&file_lock);
    }else{
	f->eax = -1;
    }
  }
}

//////////////////////////// SEEK \\\\\\\\\\\\\\\\\\\\\\\/

void seek(struct intr_frame *f, int* esp) {
  int fd = *(esp + 1);
  unsigned int position = *(esp + 2);

  if ( !check_ptr(esp+1) || !check_ptr(esp+2) ) {
    exit(-1);
    return;
  }

  else { 
    struct file *file=NULL;
    file = getFilePtr(fd);
    if(file){
        lock_acquire(&file_lock);
	file_seek (file,position) ;
	lock_release(&file_lock);
    }else{
	f->eax = -1;
    }
  } 
}

//////////////////////////// WAIT \\\\\\\\\\\\\\\\\\\\\\\/
void wait(struct intr_frame *f, int* esp) {
  
  if ( !check_ptr(esp+1)) {
     exit(-1);
    return;
  }	
  else{	
    
    lock_acquire(&proc_lock); 
    f->eax = process_wait(*(esp + 1));
    lock_release(&proc_lock);

  }
}

//////////////////////////// EXECUTE \\\\\\\\\\\\\\\\\\\\\\\/
void exec(struct intr_frame *f, int* esp) {
 char* file_name = *(esp + 1);
 
  
  if (!check_ptr(file_name) ){    
    f->eax=-1;
    return;
  }
  
 /* struct file *myFile = filesys_open(copy(file_name)); //opening the file for checking whether it exists
  if(!myFile){ //checking if file pointer is valid for execute missing
   f->eax = -1;
   return;
  }
  palloc_free_page(file_copy);*/
  lock_acquire(&proc_lock);
  f->eax = process_execute (file_name);
  lock_release(&proc_lock);
       
  
}


//////////////////////////// FILESIZE ///////////////////////
/*
* Checks the length of file in bytes
* Used in read function
*
*////////////////////////////////////////////////////////////
void filesize(struct intr_frame *f, int* esp) {
 int fd = *(esp + 1);
  if (!check_ptr(esp+1)) {
    exit(-1);
    return;
  }
 
  else {
    struct file *file=NULL;
    file = getFilePtr(fd);
    if(file){
        lock_acquire(&file_lock);
	f->eax = file_length (file) ;
	lock_release(&file_lock);
    }else{
	f->eax = -1;
    }
  }
}

//////////////////////////// TELL \\\\\\\\\\\\\\\\\\\\\\\/
void tell(struct intr_frame *f, int* esp) {
 int fd = *(esp + 1);
  if (!check_ptr(esp+1)) {
    exit(-1);
    return;
  }
 
  else {  
    struct file *file=NULL;
    file = getFilePtr(fd);
    if(file){
        lock_acquire(&file_lock);
	f->eax = file_tell (file) ;
      	lock_release(&file_lock);
    }else{
	f->eax = -1;
    } 
  }
}

//////////////////////////// REMOVE \\\\\\\\\\\\\\\\\\\\\\\/
void remove(struct intr_frame *f, int* esp) {
 char *file = *(esp + 1);
  if (!check_ptr(esp+1)) {
    exit(-1);
    return;
  }
  if (strlen(file) == 0)
  {
    f->eax = -1;
    return;
  }
  else {
        lock_acquire(&file_lock);
	f->eax = filesys_remove(file) ;
      	lock_release(&file_lock);
      }    
      
}
    
//////////////////////////// CLOSE \\\\\\\\\\\\\\\\\\\\\\\/  
void close(struct intr_frame *f, int* esp) {
  int fd = *(esp + 1);
  if (!check_ptr(fd)) {
    exit(-1);
    return;
  }
  else {
    struct file *file=NULL;
    file = getFilePtr(fd);
    if(file){
      lock_acquire(&file_lock);
      
      int i=0;
      for(i=3;i<131;i++){
	file_close (fd_file_ptrs[i]);
      	fd_file_ptrs[i] = NULL;
      }
      file = NULL;
      lock_release(&file_lock);
      return;
    }else{
	f->eax = -1;
    }
  }	
}
  

void add_process_to_list(const char* name, tid_t tid) {
  struct process_info *pi  = (struct process_info*) malloc (sizeof(struct process_info));
  pi->exit_code = -1000;
  pi->pid = tid;

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

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  list_init(&process_info_list);
  lock_init(&pil_lock);
  lock_init(&proc_lock);
  lock_init(&file_lock);
}



void exit(int exit_code) {
  set_process_exitcode(thread_current()->tid, exit_code);
  struct process_info* pi = get_process_info(thread_current()->tid) ;

  printf("%s: exit(%d)\n", pi->name , exit_code);
  thread_exit();
} 





static void
syscall_handler (struct intr_frame *f)
{
  int* esp = f->esp;
 
  if ( !check_ptr(esp)) {
    //You have to implement the exit function.
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
  else if (number == SYS_WRITE) {
    write(f, esp);
  }
  else if (number == SYS_CREATE) {
   create(f, esp);
  }
  else if (number == SYS_OPEN) {
    open(f,esp);
  }
  else if (number == SYS_READ) {
    read(f, esp);
  }
  else if (number == SYS_WAIT) {
    wait(f, esp);
  }
  else if (number == SYS_EXEC) {
    exec(f, esp);
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
  else if (number == SYS_REMOVE) {
    remove(f, esp);
  }
 
}
