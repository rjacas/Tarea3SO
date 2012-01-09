#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "devices/shutdown.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"   //incluido segun pag 4 de la tarea
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "threads/malloc.h"
/*+++++++++++++++++++++++++++++++++++++++++++++++++++++++*/
#include "filesys/file.h"
#include "filesys/filesys.h"
#include <stdbool.h>
#include <string.h>
#include <list.h>
/*+++++++++++++++++++++++++++++++++++++++++++++++++++++++*/

static void syscall_handler(struct intr_frame *);

static void my_halt (struct intr_frame *f);
static void my_exit (struct intr_frame *f);
static void my_exec (struct intr_frame *f);
static void my_wait (struct intr_frame *f);
static void my_write (struct intr_frame *f);

/*+++++++++++++++++++++++++++++++++++++++++++++++++++++++*/
static void my_create(struct intr_frame *f);
static void my_remove(struct intr_frame *f);
static void my_open(struct intr_frame *f);
static void my_filesize(struct intr_frame *f);
static void my_seek(struct intr_frame *f);
static void my_tell(struct intr_frame *f);
static void my_close(struct intr_frame *f);
static void my_read(struct intr_frame *f); 
static int get_fd();
static struct file *find_file_by_fd (int fd);
static struct my_fd *find_fd_elem_by_fd (int fd);
static struct fd_elem *find_fd_elem_by_fd_in_process (int fd);
struct list fd_list;
int cur_fd;
/*+++++++++++++++++++++++++++++++++++++++++++++++++++++++*/

/* Condiciones de acceso a mem de usuario */
static bool dir_valida(void *ptr)
{
  return (ptr != NULL && is_user_vaddr(ptr) && pagedir_get_page(thread_current()->pagedir, ptr));
}

void syscall_init(void) {
	intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
/*+++++++++++++++++++++++++++++++++++++++++++++++++++++++*/
  list_init(&fd_list);
/*+++++++++++++++++++++++++++++++++++++++++++++++++++++++*/
}

static void
syscall_handler (struct intr_frame *f UNUSED)
{
	//printf ("system call!\n");

	int num_llamada;
	/* Primero chequear que el stack sea una direccion valida */
	if (!dir_valida(f->esp)) {
		//printf("Direccion invalida de stack!\n");
		syscall_simple_exit (f, -1);
		thread_exit();
	}

	num_llamada = *((int *) f->esp);
	//printf("Llamada a sistema numero: %d\n", num_llamada);
	switch (num_llamada) {
		case SYS_HALT:
		  my_halt(f);
		  break;
		case SYS_EXIT:
		  my_exit(f);
		  break;
		case SYS_EXEC:
		  my_exec(f);
		  break;
		case SYS_WAIT:
		  my_wait(f);
		  break;
		case SYS_WRITE:
		  my_write(f);
		  break;
/*+++++++++++++++++++++++++++++++++++++++++++++++++++++++*/
		case SYS_CREATE:
		  my_create(f);
		  break;
		case SYS_REMOVE:
		  my_remove(f);
		  break;
		case SYS_OPEN:
		  my_open(f);
		  break;
		case SYS_FILESIZE:
		  my_filesize(f);
		  break;
		case SYS_SEEK:
		  my_seek(f);
		  break;
		case SYS_TELL:
		  my_tell(f);
		  break;
		case SYS_CLOSE:
		  my_close(f);
		  break;
    case SYS_READ:
      my_read(f);
      break;
/*+++++++++++++++++++++++++++++++++++++++++++++++++++++++*/		
		default:
		  printf("AUN NO IMPLEMENTADO\n");
		  thread_exit ();
		  break;
	}
	
}

void
syscall_simple_exit (struct intr_frame *f, int status)
{
  /* Impresion pedida */
  printf("%s: exit(%d)\n", thread_name (), status);

  /* Hay que liberar recursos antes de morir */
  struct thread *t = thread_current ();
 
  struct list_elem *e;
  struct child_elem *c_elem;
  struct wait_child_elem *w_elem;

  while (!list_empty (&t->children_list))
  {
    e = list_pop_back (&t->children_list);
    c_elem = list_entry (e, struct child_elem, elem);
    remove_from_exit_list(c_elem->pid);
    free (c_elem);
  }
  
  while (!list_empty (&t->waited_children_list))
  {
    e = list_pop_back (&t->waited_children_list);
    w_elem = list_entry (e, struct wait_child_elem, elem);
    free (w_elem);
  }
  put_on_exited_list (t->tid, status);
  
  thread_exit ();
  f->eax = status;
}

static void my_halt (struct intr_frame *f UNUSED){
	shutdown_power_off ();
}

static void my_exit (struct intr_frame *f){
  int status;
  if (!dir_valida (f->esp + sizeof (int)))
    status = -1;
  else
    status = *(int *) (f->esp + sizeof (int));

  syscall_simple_exit (f, status);
}

static void my_exec (struct intr_frame *f){
	char *cmd;
	tid_t pid;
	
	/* Chequeo de direcciones: */
	if (!dir_valida (f->esp + sizeof (int)))
  {
    syscall_simple_exit (f, -1);
    return;
  }
  
  /* Se recupera el comando para ejecutar */
  cmd = *(void **)(f->esp + sizeof(void *));
  
  /* Validarlo */
  if (!dir_valida(cmd))
  {
    syscall_simple_exit(f, -1);
    return;
  }
  
  /* Ejecutar */
  pid = process_execute(cmd);
  
  /* Caso de error */
  if (pid == TID_ERROR)
  {
    f->eax = -1; /* Retorno al padre */
    return;
  }
  
  f->eax = pid;
}

static void my_wait (struct intr_frame *f UNUSED){
	tid_t pid;

  if (!dir_valida (f->esp + sizeof(int)))
  {
    syscall_simple_exit(f, -1);
    return;
  }
  
  pid = *(int *)(f->esp + sizeof(int));
  struct thread *t = thread_current ();
    
  struct list_elem *e;
  struct child_elem *c_elem;
  struct wait_child_elem *waited_c_elem;

  for (e = list_begin (&t->children_list); 
       e != list_end (&t->children_list);
       e = list_next (e))
  {
    /* Recupero un hijo */
    c_elem = list_entry (e, struct child_elem, elem);
    /* Si el que me piden esperar era mi hijo ... */
    if (c_elem->pid == pid)
      {
        /* Veo si ya lo estaba esperando o no */
        struct list_elem *waited_e;
        for (waited_e = list_begin (&t->waited_children_list); 
             waited_e != list_end (&t->waited_children_list);
             waited_e = list_next (waited_e))
        {
          waited_c_elem = list_entry (waited_e, struct wait_child_elem, elem);
          /* Si ya lo estaba esperando, es un error */
          if (waited_c_elem->pid == pid) 
          {
            f->eax = -1;
            return;
          }
        }

        /* Si llego aca es porque era mi hijo y no lo estaba esperando,
          asi que lo esperare */
        struct wait_child_elem *new_wait_c_elem;
        if ((new_wait_c_elem = (struct wait_child_elem *) malloc(sizeof(struct wait_child_elem))) == NULL)
        {
          syscall_simple_exit(f, -1);
          return;
        }

        /* Lo pongo en la lista de esperados */
        new_wait_c_elem->pid = pid;
        list_push_back (&t->waited_children_list, &new_wait_c_elem->elem);
        f->eax = process_wait (pid); 
        return;
      }
  }
  /* Si llego aca es porque me mandaron a esperar un thread que no era mi hijo */
  f->eax = -1;
	return;
}
static void my_write (struct intr_frame *f){
  struct file *fl;

	// se verifica que todos los argumentos apunten a direcciones validas
  if (!dir_valida (f->esp + 5*sizeof (int)) ||
      !dir_valida (f->esp + 6 * sizeof (int)) ||
      !dir_valida (f->esp + 6 * sizeof (int) + sizeof (void *)))
    {
      syscall_simple_exit (f, -1);
      return;
    }
//printf("Veamos como viene el stack...\n");
//hex_dump((unsigned int)f->esp, f->esp, 100, 1);

  int fd = *(int *) (f->esp + 5*sizeof (int));
  const void *buffer = *(void **) (f->esp + 6 * sizeof (int));
  unsigned length = *(int *) (f->esp + 6 * sizeof (int) +
                              sizeof (void *));

/*+++++++++++++++++++++++++++++++++++++++++++++++++++++++*/
  if(fd == 0){
	syscall_simple_exit (f, -1);
    return;
  }
/*+++++++++++++++++++++++++++++++++++++++++++++++++++++++*/
  if (fd == 1){
    putbuf(buffer, length);
    /* Retorna numero de bytes escritos */
/*+++++++++++++++++++++++++++++++++++++++++++++++++++++++*/
    f->eax = length;
/*+++++++++++++++++++++++++++++++++++++++++++++++++++++++*/
  }
  else {
/*+++++++++++++++++++++++++++++++++++++++++++++++++++++++*/
	f->eax = -1;
	
	fl = find_file_by_fd(fd);
	struct my_fd *myfd = find_fd_elem_by_fd(fd);
	
	if (!fl){
	  syscall_simple_exit (f, -1);
	  return;
	}
    //~ printf("name %s\n",thread_current()->name);
    //~ printf("name2 %s\n",myfd->name);
	if(strcmp(thread_current()->name,myfd->name)==0){
	  f->eax = 0;
	  return;
	}
	
	unsigned offset = file_write (fl, buffer, length);     
    f->eax = offset; 
/*+++++++++++++++++++++++++++++++++++++++++++++++++++++++*/    
  }
  
   
}


/*+++++++++++++++++++++++++++++++++++++++++++++++++++++++*/
static void my_create(struct intr_frame *f){

  if (!dir_valida (f->esp + 4 * sizeof (void *)) ||
      !dir_valida (f->esp + 5 * sizeof (int)))
    {
      syscall_simple_exit (f, -1);
      f->eax = false;
    }

  //hex_dump((unsigned int)f->esp, f->esp, 300, 1);

  char *fi = *(void **) (f->esp + 4 * sizeof (void *));
  unsigned initial_size = *(int *) (f->esp + 5 * sizeof (int));

  //printf("creating %s with size %d\n",(char*)fi,initial_size);

  if (!fi || *fi == '\0'){
    syscall_simple_exit(f,-1);
    f->eax = false;
  }
  if(strlen((char*)fi) > 14){
    f->eax = false;
  }
  f->eax = filesys_create ((char*)fi, initial_size);
}

static void my_remove(struct intr_frame *f){

  if (!dir_valida (f->esp + 4 * sizeof (void *)))
    {
      syscall_simple_exit (f, -1);
      f->eax = false;
    }

  //hex_dump((unsigned int)f->esp, f->esp, 300, 1);

  char *fi = *(void **) (f->esp + 4 * sizeof (void *));

  //printf("removing %s\n",(char*)fi);

  if (!fi || *fi == '\0'){
    f->eax = false;
  }
  if(strlen((char*)fi) > 14){
    f->eax = false;
  }
  if (!is_user_vaddr (fi))
    syscall_simple_exit(f,-1);

  f->eax = filesys_remove ((char*)fi);
}

static void my_open(struct intr_frame *f){
  struct file *fil;
  struct my_fd *fd;

  if (!dir_valida (f->esp + 1 * sizeof (void *)))
    {
      syscall_simple_exit (f, -1);
      f->eax = false;
    }

  //hex_dump((unsigned int)f->esp, f->esp, 300, 1);

  char *fi = *(void **) (f->esp + 1 * sizeof (void *));

  //~ printf("opening %s\n",(char*)fi); 
  
  f->eax = -1;
  if (!fi)
    return;
  fil = filesys_open (fi);
  if (!fil)
    return;
    
  fd = (struct my_fd *)malloc (sizeof (struct my_fd));
  if (!fd) /* no queda memoria */
    {
      file_close (fil);
      return;
    }
    
  fd->f = fil;
  fd->value = get_fd();
  strlcpy (fd->name, fi,14);
  list_push_back (&fd_list, &fd->elem);
  list_push_back (&thread_current ()->fd_list, &fd->thread_elem);
  f->eax = fd->value;
}

static void my_filesize(struct intr_frame *f){
	
  struct file *fl;
  
  if (!dir_valida (f->esp + 1 * sizeof (int)))
    {
      syscall_simple_exit (f, -1);
      f->eax = false;
    }

  //hex_dump((unsigned int)f->esp, f->esp, 300, 1);

  int fd = *(int *) (f->esp + 1 * sizeof (int));

  //~ printf("filelength %s\n",fd); 
  
  f->eax = -1;
  if(fd < 2)
	return;
	
  fl = find_file_by_fd (fd);
  if (!f)
    return;

  f->eax = file_length (fl);
	
}

static void my_seek(struct intr_frame *f){
	
  struct file *fl;

	// se verifica que todos los argumentos apunten a direcciones validas
  if (!dir_valida (f->esp + 5*sizeof (int)) ||
      !dir_valida (f->esp + 6 * sizeof (int)))
    {
      syscall_simple_exit (f, -1);
      return;
    }
//printf("Veamos como viene el stack...\n");
//hex_dump((unsigned int)f->esp, f->esp, 100, 1);

  int fd = *(int *) (f->esp + 5*sizeof (int));
  unsigned new_pos = *(int *) (f->esp + 6 * sizeof (int));


  if(fd < 2){
	syscall_simple_exit (f, -1);
    return;
  }

	
  fl = find_file_by_fd(fd);
	
  if (!fl){
    syscall_simple_exit (f, -1);
	return;
  }
		
  file_seek (fl, new_pos);

}

static void my_tell(struct intr_frame *f){
  struct file *fl;

  // se verifica que todos los argumentos apunten a direcciones validas
  if (!dir_valida (f->esp + 5*sizeof (int)))
    {
      syscall_simple_exit (f, -1);
      return;
    }
//printf("Veamos como viene el stack...\n");
//hex_dump((unsigned int)f->esp, f->esp, 100, 1);

  int fd = *(int *) (f->esp + 5*sizeof (int));
  
  if(fd < 2){
	syscall_simple_exit (f, -1);
    return;
  }

	
  fl = find_file_by_fd(fd);
	
  if (!fl){
    syscall_simple_exit (f, -1);
	return;
  }
	
  file_tell (fl);
}

static void my_close(struct intr_frame *f){
  struct my_fd *myfd;

  // se verifica que todos los argumentos apunten a direcciones validas
  if (!dir_valida (f->esp + 3*sizeof (int)))
    {
      syscall_simple_exit (f, -1);
      return;
    }
  
//hex_dump((unsigned int)f->esp, f->esp, 100, 1);

  int fd = *(int *) (f->esp + 3*sizeof (int));
  
  //printf("closing fd %d\n",fd);
  
  if(fd < 2){
	syscall_simple_exit (f, -1);
    return;
  }

	
  myfd = find_fd_elem_by_fd_in_process (fd);
  
  if (!myfd){
    syscall_simple_exit (f, -1);
    return;
  }
  
  file_close (myfd->f);
  list_remove (&myfd->elem);
  list_remove (&myfd->thread_elem);
  free (myfd);
}

static void my_read(struct intr_frame *f){
  struct file *fl;
  int i;

  if (!dir_valida (f->esp + 5 * sizeof (int)) ||
      !dir_valida (f->esp + 6 * sizeof (int)) ||
      !dir_valida (f->esp + 6 * sizeof (int) + sizeof (void *)))
    {
      syscall_simple_exit (f, -1);
      return;
    }

  int fd = *(int *) (f->esp + 5 * sizeof (int));
  const void *buffer = *(void **) (f->esp + 6 * sizeof (int));
  unsigned length = *(int *) (f->esp + 6 * sizeof (int) +
                              sizeof (void *));
  
  if(fd == 1){
	syscall_simple_exit (f, -1);
    return;
  }
  if (fd == 0){
    for (i = 0; i != length; ++i)
      *(uint8_t *)(buffer + i) = input_getc ();
    f->eax = length;
  }
  else {

	f->eax = -1;
	fl = find_file_by_fd(fd);

	if (!fl){
	  syscall_simple_exit (f, -1);
	  return;
	}

  if(!dir_valida(buffer)){
    syscall_simple_exit (f, -1);
    return;
  }    

	unsigned offset = file_read(fl,(void *) buffer, length);     
    f->eax = offset;  
  }

}

static int get_fd(){
  if(cur_fd == NULL)
    cur_fd = 2;
  return ++cur_fd;
} 

static struct file *
find_file_by_fd (int fd)
{
  struct my_fd *ret;
  
  ret = find_fd_elem_by_fd (fd);
  if (!ret)
    return NULL;
  return ret->f;
}

static struct my_fd *
find_fd_elem_by_fd (int fd)
{
  struct my_fd *ret;
  struct list_elem *l;
  
  for (l = list_begin (&fd_list); l != list_end (&fd_list); l = list_next (l))
    {
      ret = list_entry (l, struct my_fd, elem);
      if (ret->value == fd)
        return ret;
    }
    
  return NULL;
}

static struct fd_elem *
find_fd_elem_by_fd_in_process (int fd)
{
  struct my_fd *ret;
  struct list_elem *l;
  struct thread *t;
  
  t = thread_current ();
  
  for (l = list_begin (&t->fd_list); l != list_end (&t->fd_list); l = list_next (l))
    {
      ret = list_entry (l, struct my_fd, thread_elem);
      if (ret->value == fd)
        return ret;
    }
    
  return NULL;
}


/*+++++++++++++++++++++++++++++++++++++++++++++++++++++++*/


