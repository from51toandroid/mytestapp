
#include <stdio.h>  
#include <stdlib.h>  
#include <asm/user.h>  
#include <asm/ptrace.h>  
#include <sys/ptrace.h>  
#include <sys/wait.h>  
#include <sys/mman.h>  
#include <dlfcn.h>  
#include <dirent.h>  
#include <unistd.h>  
#include <string.h>  
#include <elf.h>  
#include <android/log.h>  


#include <malloc.h>
#include <string.h>
#include <stdlib.h>
#include <dlfcn.h>

#include <cutils/compiler.h>
#include <cutils/properties.h>

#include <utils/Log.h>






#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <android/log.h>
#include <EGL/egl.h>
#include <GLES/gl.h>
#include <elf.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <termios.h>

#define LOG_TAG "DEBUG"
#define LOGD(fmt, args...) printf(fmt, ##args)  





#define Ser_Printf   printf
#define macdbg_prser printf

#define my_printf printf

static int g_com_fd = -1;



int main(int argc, char** argv);
extern int my_tgkill(int);


/* p_type */
#define PT_NULL_STR		"NULL"		
/* Program header table entry unused */

#define PT_LOAD_STR		"LOAD"		
/* Loadable program segment */


#define PT_DYNAMIC_STR  "DYNAMIC"		
/* Dynamic linking information */

#define PT_INTERP_STR       "INTERP"	
/* Program interpreter */


#define PT_NOTE_STR		"NOTE"		
/* Auxiliary information */

#define PT_SHLIB_STR	"SHLIB"	
/* Reserved, unspecified semantics */

#define PT_PHDR_STR		"PHDR"		
/* Entry for header table itself */

#define PT_TLS_STR		"TLS"		
/* TLS initialisation image */


#define PT_NUM_STR		"NUM"

#define PT_GNU_EH_FRAME_STR		"GNU_EH_FRAME"
#define PT_GNU_STACK_STR		"GNU_STACK"
#define PT_GNU_RELRO_STR		"GNU_RELRO"

#define PT_ARM_EXIDX_STR		"EXIDX"


#define HELLO_LIBSF_PATH    "/system/bin/asmhello"


#ifndef PT_ARM_EXIDX
#define PT_ARM_EXIDX 0x70000001
#endif


#define PT_NULL		0		/* Program header table entry unused */
#define PT_LOAD		1		/* Loadable program segment */
#define PT_DYNAMIC	2		/* Dynamic linking information */
#define PT_INTERP	3		/* Program interpreter */
#define PT_NOTE		4		/* Auxiliary information */
#define PT_SHLIB	5		/* Reserved, unspecified semantics */
#define PT_PHDR		6		/* Entry for header table itself */
#define PT_TLS		7		/* TLS initialisation image */
#define PT_NUM		8

#define PT_GNU_EH_FRAME 0x6474e550	/* EH frame segment */
#define PT_GNU_STACK	0x6474e551	/* Indicate executable stack */
#define PT_GNU_RELRO	0x6474e552	/* Make read-only after relocation */

char *get_p_type(int type)
{
    char *pp_type = NULL;
    switch (type)
    {  
      case  PT_NULL:
        pp_type = PT_NULL_STR;
      break;
      case  PT_LOAD:
        pp_type = PT_LOAD_STR;
      break;
      case  PT_DYNAMIC:
        pp_type = PT_DYNAMIC_STR;
      break;
      case  PT_INTERP:
        pp_type = PT_INTERP_STR;
      break;
      case  PT_NOTE:
        pp_type = PT_NOTE_STR;
      break;
      case  PT_SHLIB:
        pp_type = PT_SHLIB_STR;
      break;
      case  PT_PHDR:
        pp_type = PT_PHDR_STR;
      break;
      case  PT_TLS:
        pp_type = PT_TLS_STR;
      break;
      case  PT_NUM:
        pp_type = PT_NUM_STR;
      break;
      case  PT_GNU_EH_FRAME:
        pp_type = PT_GNU_EH_FRAME_STR;
      break;
      case  PT_GNU_STACK:
        pp_type = PT_GNU_STACK_STR;
      break;
      case  PT_GNU_RELRO:
        pp_type = PT_GNU_RELRO_STR;
      break;
      case  PT_ARM_EXIDX:
        pp_type = PT_ARM_EXIDX_STR;
      break;
                
      default:
        pp_type = NULL;
      break;
    }
    return pp_type;
}



int macdbg_dmphex(const char* buff, int len)
{
    int retval = 0; 
    int x, y, tot, lineoff;
    const char* curr;
    
    Ser_Printf( "buff addr = 0x%x.\r\n", buff );

	Ser_Printf("\r\n" );
    lineoff = 0;
    curr = buff;
    tot = 0;
    for( x = 0; x+16 < len; ){   
         Ser_Printf("%x\t", lineoff);
         for( y = 0; y < 16; y++ ){
              macdbg_prser("%02x ", (unsigned char)*(curr + y));
         }
         macdbg_prser("  ");
         for( y = 0; y < 16; y++ ){
              char c;
              c = *(curr + y);
              if( c > 31 && c < 127 ){
                  macdbg_prser("%c", c);
              }else{
                  macdbg_prser("%c", '.');
              }
              tot++;
         }
         curr += 16;
         x += 16;
         lineoff+=16;
         macdbg_prser("\r\n");
    }
    
    //do last line

	//Ser_Printf("tot %d.\r\n", tot );
	//Ser_Printf("len %d.\r\n", len );
    if( tot < len ){
        curr = (buff + tot);
        macdbg_prser("%x\t", lineoff);
        for( y = 0; y < (len - tot); y++ ){
             macdbg_prser("%02x ", (unsigned char)*(curr + y));
        }
        //padding with spaces
        //Ser_Printf("(len - tot) %d.\r\n", (len - tot) );
        if( (len - tot) < 16 ){
            for( y = 0; y < (32 - ((len - tot)*2)); y++ ){
                 macdbg_prser(" ");
            }
        }
        for( y = 0; y < 16-(len - tot); y++ ){
             macdbg_prser(" ");
        }

	   
        macdbg_prser("  "); 
	   //Ser_Printf("(len - tot) %d.\r\n", (len - tot) );
        for( y = 0; y < (len - tot); y++ ){
            char c;
            c = *(curr + y);
            if( c >31 && c < 127 ){
                macdbg_prser("%c", c);
            }else{
                macdbg_prser("%c", '.');
			  //macdbg_prser("%c", c);
            }
        }
    }
    macdbg_prser("\r\n");	
    return retval;
}







void old_funpoint(void)
{
    printf( "in old_funpoint.\n" );
}


void new_funpoint(void)
{
    printf( "in new_funpoint.\n" );
}

void* hello_get_module_base(pid_t pid, const char* module_name)
{
    FILE *fp;
    long addr = 0;
    char *pch;
    char filename[32];
    char line[1024];

    if (pid < 0) {
        /* self process */
        snprintf(filename, sizeof(filename), "/proc/self/maps", pid);
    } else {
        snprintf(filename, sizeof(filename), "/proc/%d/maps", pid);
    }

    fp = fopen(filename, "r");

    if (fp != NULL) {
        while (fgets(line, sizeof(line), fp)) {
            if (strstr(line, module_name)) {
                pch = strtok( line, "-" );
                addr = strtoul( pch, NULL, 16 );

                if (addr == 0x8000)
                    addr = 0;

                break;
            }
        }

        fclose(fp) ;
    }

    return (void *)addr;
}



//#define LIBSF_PATH    "/system/lib/libsurfaceflinger.so"





int hook_hello()
{
    //old_funpoint = NULL;
    //LOGD("Orig eglSwapBuffers = %p\n", old_funpoint);            
    void * base_addr = hello_get_module_base(getpid(), HELLO_LIBSF_PATH);
    LOGD("asmhello address = %p\n", base_addr);
    //macdbg_dmphex(base_addr, 0x1000);                                                      
    int fd;
    fd = open(HELLO_LIBSF_PATH, O_RDONLY);
    if( -1 == fd ){
        LOGD("error\n");
        return -1;   
    }
	
    Elf32_Ehdr ehdr;
    read(fd, &ehdr, sizeof(Elf32_Ehdr));

    //macdbg_dmphex(&ehdr, sizeof(Elf32_Ehdr));


    //以下代码主要分析段头数据结构
    unsigned long shdr_addr = ehdr.e_shoff;
    int shnum = ehdr.e_shnum;
    //Number of section headers
    //段头项目的个数
    int shent_size = ehdr.e_shentsize;
    //Section header entry size
    //每一个段头项目的大小      
     	
    unsigned long stridx = ehdr.e_shstrndx;

    Elf32_Shdr shdr;
    //my_printf( "ehdr.e_phoff = %x\n", ehdr.e_phoff );
    //程序头偏移地址,直接跟随ELF Header 0x34
    //ELF Header占用52字节,描述程序头,段头,体系结构等信息
    //my_printf( "ehdr.e_phnum = %x\n", ehdr.e_phnum );
    //程序头结构体的个数
    //my_printf( "ehdr.e_phentsize = %x\n", ehdr.e_phentsize );
    //程序头结构体每一个的大小
	
    //my_printf( "shdr_addr = %x\n", shdr_addr );
    //段头的偏移地址
    //my_printf( "shnum = %x\n", shnum );
    //段头结构体的个数
    //my_printf( "shent_size = %x\n", shent_size );
    //每一个段头结构体的大小
    //my_printf( "stridx = %x\n", stridx );
    //Section header string table index: 23
    //在所有段头结构体内,有一个叫"串表"的结构体
    //此结构体在所有段头结构体的个数中的索引值 指向最后一个段头结构体
    //此调试信息可以看出-->shnum = 18 shent_size = 28 stridx = 17

    //my_printf( "shdr_addr = %x\n", shdr_addr );
    //my_printf( "shdr_addr + stridx * shent_size = %x\n", shdr_addr + stridx * shent_size );
    lseek(fd, shdr_addr + stridx * shent_size, SEEK_SET);
    //文件指针定位到"串表"段头结构体
    read(fd, &shdr, shent_size);
    //读取"串表"段头结构体



				   
    char *string_table = (char *)malloc(shdr.sh_size);
    //my_printf( "string_table = %x\n", string_table );
    //my_printf( "shdr.sh_size = %x\n", shdr.sh_size );
    //section size,串表的大小 描述了串表占用的存储空间的大小
    //my_printf( "shdr.sh_offset = %x\n", shdr.sh_offset );
    //file offset 串表在整个elf文件中的偏移位置
      
                  	
    lseek(fd, shdr.sh_offset, SEEK_SET);           
    read(fd, string_table, shdr.sh_size);
    lseek(fd, shdr_addr, SEEK_SET);
    //指向段头结构体存储的首地址
    
     
    //elf内存结构描述如下:
    //-->开始
    //ELF Header 0x34
    //程序头结构体存储位置:
    //PHDR->第一个程序头结构体
    //描述了总共有多少个程序头结构体
    //INTERP->第二个程序头结构体
    //描述了linker在系统中的位置                      
                                                       	
    //整个串表   
    //段头结构体存储位置:
    //第一个段头表入口为空
    //->Section header table entry unused
    
    //.interp   
    //.dynsym
    //.dynstr
    //.hash
    //.rel.dyn
    //.rel.plt
    //.plt
    
    //.text
    //->函数执行代码 
    
    //.note.android.ident
    //.ARM.exidx
    //->部分函数地址可以在此用公式获取

	
    //.ARM.extab
    
    //.rodata
    //->全局const变量 字符串等 printf("test string");
    //->程序本身的一些表 看情况
                 
    //.preinit_array
    //.init_array
    //.fini_array
    //.dynamic
    
    //.got
    //->动态库相关的函数地址
    
    //.bss
    //->未初始化的全局变量
    
    //.comment
    //.note.gnu.gold-version
    //.ARM.attributes
    //.gnu_debuglink
    
    //.shstrtab
    //->串表描述
    //-->结束    

    
	
    int i,j;                          
    uint32_t out_addr = 0;                    
    uint32_t out_size = 0;             
    uint32_t got_item = 0;                
    int32_t got_found = 0;     
    int32_t get_off = 0;   

    //my_printf( "shnum = %x\n", shnum );
    //段头结构体的个数 0x18
    //my_printf( "shent_size = %x\n", shent_size );
    //每一个段头结构体的大小 0x28
    for( j = 0; j < shnum; j++ ){
         read(fd, &shdr, shent_size);
         //macdbg_dmphex(&shdr, sizeof(Elf32_Shdr));  
         //my_printf( "shdr.sh_type = %x\n", shdr.sh_type );
         int name_idx = shdr.sh_name;  
         if( shdr.sh_type == SHT_PROGBITS ){
             //my_printf( "get Section header entry %s\n", &string_table[name_idx] );
             //my_printf( "shdr.sh_addr = %x\n", shdr.sh_addr );
             //my_printf( "shdr.sh_offset = %x\n", shdr.sh_offset );
             //my_printf( "shdr.sh_size = %x\n", shdr.sh_size );
             //my_printf( "shdr.sh_entsize = %x\n", shdr.sh_entsize );
             if( strcmp(&(string_table[name_idx]), ".got.plt") == 0 || 
                 strcmp(&(string_table[name_idx]), ".got") == 0 ){
                 out_addr = base_addr + shdr.sh_addr;
                 out_size = shdr.sh_size;
                LOGD("out_addr = %lx, out_size = %lx\n", out_addr, out_size);
			  //my_printf( "old_funpoint = %x\n", old_funpoint );
			  //my_printf( "new_funpoint = %x\n", new_funpoint );
			  my_printf( "base_addr = %x\n", base_addr ); 	
			  my_printf( "main = %x\n", main ); 
			  //macdbg_dmphex( base_addr, 0x40000);
                for (i = 0; i < out_size; i += 4) {
                    got_item = *(uint32_t *)(out_addr + i);
				 my_printf( "got_item = %x\n", got_item );
				 
                    if (got_item == old_funpoint) {
                        LOGD("Found eglSwapBuffers in got\n");
                        got_found = 1;
                        uint32_t page_size = getpagesize();
                        uint32_t entry_page_start = (out_addr + i) & (~(page_size - 1));
                        mprotect((uint32_t *)entry_page_start, page_size, PROT_READ | PROT_WRITE);
                        *(uint32_t *)(out_addr + i) = new_funpoint;
					 my_printf( "shnum = %x\n", shnum );
                        break;
                    } else if (got_item == new_funpoint) {
                        LOGD("Already hooked\n");
                        break;
                    }
                }
                if (got_found) { 
                    //break;
                }
            }else if( strcmp(&(string_table[name_idx]), ".rodata") == 0 ) {
                //const,固定字符串等在此段找
                my_printf("get .rodata\n");
			  macdbg_dmphex(&shdr, sizeof(Elf32_Shdr));  
            }
			
        }else if (shdr.sh_type == SHT_NULL) {
            //Section header table entry unused
            //第一个段头表入口为空
            my_printf("get null\n");
        }else if (shdr.sh_type == PT_ARM_EXIDX) {
            //Section header table entry unused
            //第一个段头表入口为空
            
            my_printf( "macdbg_dmphex = %x\n", macdbg_dmphex );
            my_printf( "old_funpoint = %x\n", old_funpoint );
            my_printf( "new_funpoint = %x\n", new_funpoint );
            my_printf( "hello_get_module_base = %x\n", hello_get_module_base );
            my_printf( "hook_hello = %x\n", hook_hello );
            my_printf( "main = %x\n", main );
            my_printf( "my_tgkill = %x\n", my_tgkill );
				 
            //my_printf( "get .ARM.exidx\n" );  
            //my_printf( "string_table[name_idx] = %s\n", &string_table[name_idx] );
            //my_printf( "shdr.sh_addr = %x\n", shdr.sh_addr );
            //my_printf( "shdr.sh_offset = %x\n", shdr.sh_offset );
            //my_printf( "shdr.sh_size = %x\n", shdr.sh_size );
            //my_printf( "shdr.sh_entsize = %x\n", shdr.sh_entsize );
            out_addr = base_addr + shdr.sh_addr;
            out_size = shdr.sh_size;
            my_printf("out_addr = %lx, out_size = %lx\n", out_addr, out_size); 
            
            for( i = 0; i < out_size; i += 8 ){
                 get_off = *(int32_t *)(out_addr+i);  
                 got_item = *(uint32_t *)(out_addr + i + 4);
                 //my_printf( "get_off = %x\n", get_off );
			   //my_printf( "get_off1 = %x\n", shdr.sh_addr - (~get_off +1)&0xffff )+i;
			   my_printf( "func point = %x\n", shdr.sh_addr + i - ((~get_off +1)&0xffff) + base_addr );
			   //shdr.sh_addr + i 描述函数指针的虚拟地址的偏移位置的虚拟地址
			   //*(shdr.sh_addr + i)描述函数指针的虚拟地址的偏移位置
			   //(相对于描述函数指针的虚拟地址的虚拟地址) 为负数
			   //base_addr 该进程内核内存映射的基地址
                 //my_printf( "got_item = %x\n\n", got_item );
			   //my_printf( "got_item = %d\n", got_item );
            }
        }else{                                           
            //int name_idx = shdr.sh_name;                      
			//section name (.shstrtab index)                 
		   //my_printf( "name_idx = %x\n", name_idx );
		   my_printf( "Section header entry %s\n", &string_table[name_idx] );

		   my_printf( "shdr.sh_addr = %x\n", shdr.sh_addr );
		   my_printf( "shdr.sh_offset = %x\n", shdr.sh_offset );
		   my_printf( "shdr.sh_size = %x\n", shdr.sh_size );
		   my_printf( "shdr.sh_entsize = %x\n", shdr.sh_entsize );
                
        }
    }

    free(string_table);

    //以下代码主要分析程序头数据结构
    shdr_addr = ehdr.e_phoff;
    //首个程序头项目的偏移
    shnum = ehdr.e_phnum;
    //程序头项目的个数
    shent_size = ehdr.e_phentsize;
    //每一个程序头项目的大小      
     	
    //stridx = ehdr.e_shstrndx;

	Elf32_Phdr program_shdr;
    my_printf( "ehdr.e_phoff = %x\n", ehdr.e_phoff );
    //程序头偏移地址,直接跟随ELF Header 0x34
    //ELF Header占用52字节,描述程序头,段头,体系结构等信息
    my_printf( "ehdr.e_phnum = %x\n", ehdr.e_phnum );
    //程序头结构体的个数
    my_printf( "ehdr.e_phentsize = %x\n", ehdr.e_phentsize );
    shnum = ehdr.e_phnum;
	
    lseek(fd, ehdr.e_phoff, SEEK_SET);       
    char *p_type_tmp;
    for( j = 0; j < shnum; j++ ){	
         read(fd, &program_shdr, sizeof(Elf32_Phdr));
         macdbg_dmphex(&program_shdr, sizeof(Elf32_Phdr));
         p_type_tmp = get_p_type(program_shdr.p_type);
         my_printf( "program_shdr.p_type = %s\n", p_type_tmp );
         
         my_printf( "program_shdr.p_offset = %x\n", program_shdr.p_offset );
         my_printf( "program_shdr.p_vaddr = %x\n", program_shdr.p_vaddr );
         my_printf( "program_shdr.p_paddr = %x\n", program_shdr.p_paddr );
         my_printf( "program_shdr.p_filesz = %x\n", program_shdr.p_filesz );
         my_printf( "program_shdr.p_memsz = %x\n", program_shdr.p_memsz );
         my_printf( "program_shdr.p_flags = %x\n", program_shdr.p_flags );
         my_printf( "program_shdr.p_align = %x\n", program_shdr.p_align );
         if( strcmp(p_type_tmp, PT_INTERP_STR) == 0 ){
             //程序解释器 加载器
             //描述了此程序的加载器在系统中的位置
             long temp_file_position;
             temp_file_position = lseek(fd, 0, SEEK_CUR);
             char *linker = (char *)malloc(program_shdr.p_memsz);              	
             lseek(fd, program_shdr.p_offset, SEEK_SET);           
             read(fd, linker, program_shdr.p_memsz);
             my_printf( "program loader = %s\n", linker );
             free(linker);
             lseek(fd, temp_file_position, SEEK_SET);
         }else if( strcmp(p_type_tmp, PT_PHDR_STR) == 0 ){
             //描述了此程序的程序头的整体大小
             my_printf( "get program head = %x\n", program_shdr.p_memsz );
         }

		 
    }

	
		
    //lseek(fd, shdr_addr, SEEK_SET);
    //指向段头结构体存储的首地址

	
    close(fd);
    return 0;
}





int global_test = 123;

extern int (*_start)(int);
//extern _start;
extern int __bss_start;
extern int _end;
extern int _edata;


extern int is_file_exist(const char *file_path);  


int main(int argc, char** argv) 
{
    int ret;
    //printf("asmhello.c main.\n");
    //printf( "&global_test = %x.\n", &global_test );
	//printf( "global_test = %x.\n", global_test );

    //hook_hello();
    ret = my_tgkill(3);
    
	printf( "ret = %x.\n", is_file_exist("/system/etc/init.d/////") );
	
	//printf( "&_start = %p.\n", &_start );
	//printf( "&__bss_start = %p.\n", &__bss_start );
	//printf( "&_end = %p.\n", &_end );
	//printf( "&_edata = %p.\n", &_edata );
	//printf( "&global_test = %p.\n", &global_test );

	//macdbg_dmphex( ret&0xfffff000, 0x40 );


    
	//macdbg_dmphex( ((ret-0x2000) & 0xfffff000), 0x2000);
    //printf( "printf = %x.\n", printf );
	//macdbg_dmphex((int)printf&0xfffff000, 0x18000);
    return 257;
}






#if 0
    int _src;
    _src =1;
    asm volatile(
            "nop\n"
            "mov r0, r0\n"
            "mov r0, %0\n"
         :: "r" (_src) : "r0", "r1", "r2", "r3");
         //:输出:输入:破坏的寄存器
         //"r" 告诉编译器使用寄存器处理输入变量

#endif

