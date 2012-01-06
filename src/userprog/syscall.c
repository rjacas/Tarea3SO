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
#include <stdbool.h>
#include <string.h>
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

struct list fd_list;
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


  if (fd == 1){
    putbuf(buffer, length);
  }
  else { /* Cualquier otro fd no esta implementado aun */
    syscall_simple_exit (f, -1);
    return;
  }
  
  /* Retorna numero de bytes escritos */
  f->eax = length; 
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
  return  true;
}

static void my_open(struct intr_frame *f){
  return 0;
}

static void my_filesize(struct intr_frame *f){
  return 0;
}

static void my_seek(struct intr_frame *f){

}

static void my_tell(struct intr_frame *f){
  return 0;
}

static void my_close(struct intr_frame *f){

}
/*+++++++++++++++++++++++++++++++++++++++++++++++++++++++*/


