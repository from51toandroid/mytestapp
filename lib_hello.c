
#if 0
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

//#include "AudioResamplerSinc.h"




  
#if defined(__i386__)  
xxxxxxxxxxxxx
#define pt_regs         user_regs_struct  
#endif  
  
#define ENABLE_DEBUG 1  
  
#if ENABLE_DEBUG  
#define  LOG_TAG "INJECT"  
//#define  LOGD(fmt, args...)  __android_log_print(ANDROID_LOG_DEBUG,LOG_TAG, fmt, ##args)  


#define  LOGD(fmt, args...) printf(ANDROID_LOG_DEBUG,LOG_TAG, fmt, ##args)  

//dddd
#define DEBUG_PRINT(format,args...) \  
    LOGD(format, ##args)  
#else  
#define DEBUG_PRINT(format,args...)  
#endif  
  
#define CPSR_T_MASK     ( 1u << 5 )  
  

	
	
  

  







#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
//#include <android/log.h>
#include <elf.h>
#include <fcntl.h>
#include <cutils/klog.h>


#define TAG  "htfsk"

#define LOGE(x...) do { KLOG_ERROR("events", x); } while (0)
#define LOGI(x...) do { KLOG_INFO("events", x); } while (0)
#define LOGV(x...) do { KLOG_DEBUG("events", x); } while (0)
#if 0
int debug_msg(const char *format, ...)
{	
    char tmpbuf[4096];
    unsigned int send_len;
    va_list vArgs;
    va_start(vArgs, format);				 
    vsnprintf( (char *)&tmpbuf[0], sizeof(tmpbuf), (char const *)format, vArgs );			   
    va_end(vArgs);																										
    send_len = strlen(&tmpbuf[0]);
	__android_log_write( ANDROID_LOG_DEBUG, TAG, tmpbuf );  
    return 0;
}
#endif
   

int hook_entry(char * a){
    //debug_msg("Hook success, pid = %d\n", getpid());
    //debug_msg("Hello %s\n", a);
	
	unsigned char * teststr="12345";
	__android_log_write( ANDROID_LOG_DEBUG, TAG, "hook_entry 123" ); 
	
	system("echo mabid 12345 >/dev/ttyS0");
    
	 setenv("teststr", teststr, 1);
	 
	system("echo hahah$teststr >/dev/ttyS0");
    return 19;
}

#endif

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

#include <sys/stat.h>

#include "lib_hello.h"

#include <pthread.h>



#define LOG_TAG "DEBUG"
#define LOGD(fmt, args...) my_printf(fmt, ##args)  
#define LOGI(fmt, args...) my_printf(fmt, ##args)  
#define LOGE(fmt, args...) my_printf(fmt, ##args)  






#define Ser_Printf   my_printf
#define macdbg_prser my_printf
//#define my_printf    printf

static int g_com_fd = -1;


#if 1
int my_printf( const char *fmt, ... )
{     
    char *tmp_buf;
    int g_printf_switch = 1;
    unsigned char buffer[4096];
    va_list  vArgs;
    if( g_printf_switch == 0x00 ){
        return 1;
    }
    va_start(vArgs, fmt);
    vsnprintf((char *)buffer, sizeof(buffer), (char const *)fmt, vArgs);
    va_end(vArgs);

	
    if( g_com_fd != -1 ){
        write(g_com_fd, (unsigned char *)buffer, strlen((unsigned char *)buffer) );
    }	 
    //Ser_WrStr(( unsigned  char *) buffer);  
   //setenv( "tmp_buf", buffer, 1 );
   //system( "echo $tmp_buf > /dev/ttyS0" );
   return 3;
}   

#endif




int macdbg_dmphex(const char* buff, int len)
{
    int retval = 0; 
    int x, y, tot, lineoff;
    const char* curr;
    
    Ser_Printf("\r\nout buff addr = 0x%x.\r\n", buff );
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



EGLBoolean (*old_eglSwapBuffers)(EGLDisplay dpy, EGLSurface surf) = -1;

EGLBoolean new_eglSwapBuffers(EGLDisplay dpy, EGLSurface surface)
{
    LOGD("New eglSwapBuffers\n");
    if (old_eglSwapBuffers == -1)
        LOGD("error\n");
    return old_eglSwapBuffers(dpy, surface);
}

void* get_module_base(pid_t pid, const char* module_name)
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

        fclose(fp);
    }

    return (void *)addr;
}



//shell@astar-dvk3:/data/app-lib/com.example.asus.myapplication-2 # 


//#define LIBSF_PATH    "/data/app-lib/com.example.fengzi.xdntest-1/libuart.so"

#define LIBSF_PATH1    "/data/app-lib/com.example.asus.myapplication-2/libhello-jni.so"
#define LIBSF_PATH2     "/system/lib/libtest_hello.so"

#define LIBSF_PATH     "/system/bin/htfsk"



#if 0
static int lib_hook_hello()
{
    //old_funpoint = NULL;
    //LOGD("Orig eglSwapBuffers = %p\n", old_funpoint);            
    void * base_addr = hello_get_module_base(getpid(), HELLO_LIBSF_PATH);
    LOGD("asmhello address = %p\n", base_addr);
    //macdbg_dmphex(base_addr, 0x1000);                                                      
    int fd;
    fd = open(LIBSF_PATH, O_RDONLY);
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
#endif












//从文件打开ELF
struct ElfHandle *openElfByFile(const char *path);

//释放资源
void closeElfByFile( ElfHandle *handle);


//从给定的so中获取基址,如果soname为NULL,则表示当前进程自身
ElfHandle *openElfBySoname(const char *soname);


//释放资源
void closeElfBySoname(ElfHandle *handle);


//elf关键信息
struct ElfInfo{
    const  ElfHandle *handle;	
    uint8_t *elf_base;	
    Elf32_Ehdr *ehdr;	
    Elf32_Phdr *phdr;	
    Elf32_Shdr *shdr;	
    Elf32_Dyn *dyn;	
    Elf32_Word dynsz;	
    Elf32_Sym *sym;	
    Elf32_Word symsz;	
    Elf32_Rel *relplt;	
    Elf32_Word relpltsz;	
    Elf32_Rel *reldyn;	
    Elf32_Word reldynsz;	
    uint32_t nbucket;	
    uint32_t nchain;	
    uint32_t *bucket;	
    uint32_t *chain;	
    const char *shstr;	
    const char *symstr;
};




//符号hash函数
unsigned elf_hash(const char *name);

//从section视图获取info
void getElfInfoBySectionView(struct ElfInfo *info, const  ElfHandle *handle);

//从segment视图获取info
void getElfInfoBySegmentView(struct ElfInfo *info, const  ElfHandle *handle);


//根据符号名寻找Sym
void findSymByName(struct ElfInfo *info, const char *symbol, Elf32_Sym **sym, int *symidx);

//打印section信息
void printSections(struct ElfInfo *info);


//打印segment信息
void printSegments(struct ElfInfo *info);

//打印dynamic信息
void printfDynamics(struct ElfInfo *info);

//打印所有符号信息
void printfSymbols(struct ElfInfo *info);

//打印重定位信息
void printfRelInfo(struct ElfInfo *info);



void printSections(struct ElfInfo *info)
{
     int i;
	Elf32_Half shnum = info->ehdr->e_shnum;
	Elf32_Shdr *shdr = info->shdr;

	LOGI("Sections: \n");
	for( i=0; i<shnum; i++, shdr++){
		const char *name = shdr->sh_name == 0 || !info->shstr ? "UNKOWN" :  (const char *)(shdr->sh_name + info->shstr);
		LOGI("[%.2d] %-20s 0x%.8x\n", i, name, shdr->sh_addr);
	}
}

void printSegments(struct ElfInfo *info){
	int i=0;
	Elf32_Phdr *phdr = info->phdr;
	Elf32_Half phnum = info->ehdr->e_phnum;

	LOGI("Segments: \n");
	for(i=0; i<phnum; i++){
		LOGI("[%.2d] %-20d 0x%-.8x 0x%-.8x %-8d %-8d\n", i,
				phdr[i].p_type,  phdr[i].p_vaddr,
				phdr[i].p_paddr, phdr[i].p_filesz,
				phdr[i].p_memsz);
	}
}

void printfDynamics(struct ElfInfo *info){
	int i=0;
	Elf32_Dyn *dyn = info->dyn;

	LOGI(".dynamic section info:\n");
	const char *type = NULL;

	for(i=0; i<info->dynsz; i++){
		switch(dyn[i].d_tag){
		case DT_INIT:
			type = "DT_INIT";
			break;
		case DT_FINI:
			type = "DT_FINI";
			break;
		case DT_NEEDED:
			type = "DT_NEEDED";
			break;
		case DT_SYMTAB:
			type = "DT_SYMTAB";
			break;
		case DT_SYMENT:
			type = "DT_SYMENT";
			break;
		case DT_NULL:
			type = "DT_NULL";
			break;
		case DT_STRTAB:
			type= "DT_STRTAB";
			break;
		case DT_REL:
			type = "DT_REL";
			break;
		case DT_SONAME:
			type = "DT_SONAME";
			break;
		case DT_HASH:
			type = "DT_HASH";
			break;
		default:
			type = NULL;
			break;
		}

		// we only printf that we need.
		if(type){
			LOGI("[%.2d] %-10s 0x%-.8x 0x%-.8x\n", i, type,  dyn[i].d_tag, dyn[i].d_un.d_val);
		}

		if(dyn[i].d_tag == DT_NULL){
			break;
		}
	}
}

void printfSymbols(struct ElfInfo *info)
{
     int i=0;
	Elf32_Sym *sym = info->sym;

	LOGI("dynsym section info:\n");
	for(i=0; i<info->symsz; i++){
		LOGI("[%2d] %-20s\n", i, sym[i].st_name + info->symstr);
	}
}



void printfRelInfo(struct ElfInfo *info)
{
    int i,j;    
	Elf32_Rel* rels[] = {info->reldyn, info->relplt};
	Elf32_Word resszs[] = {info->reldynsz, info->relpltsz};

	Elf32_Sym *sym = info->sym;

	LOGI("rel section info:\n");
	for( i=0; i<sizeof(rels)/sizeof(rels[0]); i++){
		Elf32_Rel *rel = rels[i];
		Elf32_Word relsz = resszs[i];

		for(j=0; j<relsz; j++){
		const char *name = sym[ELF32_R_SYM(rel[j].r_info)].st_name + info->symstr;
		LOGI("[%.2d-%.4d] 0x%-.8x 0x%-.8x %-10s\n", i, j, rel[j].r_offset, rel[j].r_info, name);
		}
	}
}




struct ElfHandle *openElfByFile(const char *path) {
	void *base = NULL;
	ElfHandle *handle = NULL;

	//此处一定不能是struct ElfHandle1 *handle = NULL;
	//否则会报dereferencing pointer to incomplete type
	int fd = open(path, O_RDWR);
	if (fd < 0) {
		LOGE("[-] open %s fails.\n", path);
		exit(-1);
	}

     struct stat fs;
	fstat(fd, &fs);

	base = mmap(NULL, fs.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
	if (base == MAP_FAILED) {
		LOGE("[-] mmap fails.\n");
		exit(-1);
	}
	close(fd);



	
 

   
   
	handle = ( ElfHandle *) malloc(sizeof( ElfHandle));
	handle->base = base;
	handle->space_size = fs.st_size;
	handle->fromfile = 1;

	return handle;
}

void closeElfByFile(ElfHandle *handle) {

	unsigned char * temp;

	
	if (handle) {
		temp = (unsigned char * )(handle->base);
		if ( temp && handle->space_size > 0) {
			msync(handle->base, handle->space_size, MS_SYNC);
			munmap(handle->base, handle->space_size);
			free(handle);
		}
	}
}







//查找soname的基址,如果为NULL,则为当前进程基址
static void *findLibBase(const char *soname) {
	FILE *fd = fopen("/proc/self/maps", "r");
	char line[256];
	void *base = 0;

	while (fgets(line, sizeof(line), fd) != NULL) {
		if (soname == NULL || strstr(line, soname)) {
			line[8] = '\0';
			base = (void *) strtoul(line, NULL, 16);
			break;
		}
	}

	fclose(fd);
	return base;
}

//从给定的so中获取基址
ElfHandle *openElfBySoname(const char *soname)
{
	void *base = findLibBase(soname);
	if(!base){
		LOGE("[-] could find %s. \n", soname);
		exit(-1);
	}

	ElfHandle *handle = (ElfHandle *) malloc(sizeof(ElfHandle));
	handle->base = base;
	//LOGE( "base = %x.\n", base );
	handle->space_size = -1;
	handle->fromfile = 0;

	return handle;
}

//释放资源
void closeElfBySoname(ElfHandle *handle){
	//only free the base
	free(handle);
}






//#define LIBSF_PATH    "/system/lib/libsurfaceflinger.so"


//#define LIBSF_PATH    "/system/lib/libtest_hello.so"

#ifndef PT_ARM_EXIDX
#define PT_ARM_EXIDX 0x70000001
#endif



//comm_spi_data_send_and_rev

//extern comm_spi_data_send_and_rev;
int hook_eglSwapBuffers()
{
    old_eglSwapBuffers = eglSwapBuffers;
    //old_eglSwapBuffers = comm_spi_data_send_and_rev;
	
    //LOGD("Orig eglSwapBuffers = %p\n", old_eglSwapBuffers);            
    void * base_addr = get_module_base(getpid(), LIBSF_PATH);
   // LOGD("libsurfaceflinger.so address = %p\n", base_addr);

    int fd;
    fd = open(LIBSF_PATH, O_RDONLY);
    if (-1 == fd) {
        LOGD("error\n");
        return -1;   
    }

    

	
    Elf32_Ehdr ehdr;
    read(fd, &ehdr, sizeof(Elf32_Ehdr));

    //macdbg_dmphex(&ehdr, sizeof(Elf32_Ehdr));


	
    unsigned long shdr_addr = ehdr.e_shoff;
    int shnum = ehdr.e_shnum;
    int shent_size = ehdr.e_shentsize;
    unsigned long stridx = ehdr.e_shstrndx;

    Elf32_Shdr shdr;

	//my_printf( "shdr_addr = %x\n", shdr_addr );
	//my_printf( "stridx = %x\n", stridx );
	//my_printf( "shent_size = %x\n", shent_size );
    lseek(fd, shdr_addr + stridx * shent_size, SEEK_SET);
    read(fd, &shdr, shent_size);
	
    char * string_table = (char *)malloc(shdr.sh_size);
	//my_printf( "string_table = %x\n", string_table );
	//my_printf( "shdr.sh_size = %x\n", shdr.sh_size );
	//my_printf( "shdr.sh_offset = %x\n", shdr.sh_offset );
    lseek(fd, shdr.sh_offset, SEEK_SET);           
    read(fd, string_table, shdr.sh_size);
    lseek(fd, shdr_addr, SEEK_SET);

    int i,j,k,l;
    uint32_t out_addr = 0;
    uint32_t out_size = 0;
    uint32_t got_item = 0, get_off=0;
    int32_t got_found = 0;
    //my_printf( "shnum = %x\n", shnum );
    for (k = 0; k < shnum; k++) {
        read(fd, &shdr, shent_size);
        int name_idx = shdr.sh_name; 
	   //my_printf( "shdr.sh_type = %x\n", shdr.sh_type );
        if (shdr.sh_type == SHT_PROGBITS) {
            
		   //my_printf( "name_idx = %x\n", name_idx );
		   //my_printf( "string_table[name_idx] = %s\n", &string_table[name_idx] );
            if (strcmp(&(string_table[name_idx]), ".got.plt") == 0 || 
			  strcmp(&(string_table[name_idx]), ".got") == 0) {
                out_addr = base_addr + shdr.sh_addr;
                out_size = shdr.sh_size;
                //LOGD("out_addr = %lx, out_size = %lx\n", out_addr, out_size);
                
                //my_printf("base_addr = %lx, shdr.sh_addr = %lx\n", base_addr, shdr.sh_addr); 
            
            for( j = 0; j < out_size; j += 4 ){
                 get_off = *(int32_t *)(out_addr+j);  
                 //my_printf( "get_off.0 = %x\n", get_off );

		        //if(j>0x100)
			   my_printf( "get_off.1 = %x\n", get_off - (uint32_t)base_addr );
			   
            }

			
			  #if 0 	
                for (i = 0; i < out_size; i += 4) {
                    got_item = *(uint32_t *)(out_addr + i);
                    if (got_item == old_eglSwapBuffers) {
                        LOGD("Found eglSwapBuffers in got\n");
                        got_found = 1;
                        uint32_t page_size = getpagesize();
                        uint32_t entry_page_start = (out_addr + i) & (~(page_size - 1));
                        mprotect((uint32_t *)entry_page_start, page_size, PROT_READ | PROT_WRITE);
                        *(uint32_t *)(out_addr + i) = new_eglSwapBuffers;
                        break;
                    } else if (got_item == new_eglSwapBuffers) {
                        LOGD("Already hooked\n");
                        break;
                    }
                }
                if (got_found) { 
                    //break;
                }
                #endif
            }
        }else if (shdr.sh_type == PT_ARM_EXIDX) {
            //Section header table entry unused
            //第一个段头表入口为空
            
            //my_printf( "macdbg_dmphex = %x\n", macdbg_dmphex );
            //my_printf( "old_funpoint = %x\n", old_funpoint );
            //my_printf( "new_funpoint = %x\n", new_funpoint );
            //my_printf( "hello_get_module_base = %x\n", hello_get_module_base );
            //my_printf( "hook_hello = %x\n", hook_hello );
            //my_printf( "main = %x\n", main );
            //my_printf( "my_tgkill = %x\n", my_tgkill );
				 
            //my_printf( "get .ARM.exidx\n" );  
            //my_printf( "string_table[name_idx] = %s\n", &string_table[name_idx] );
            //my_printf( "shdr.sh_addr = %x\n", shdr.sh_addr );
            //my_printf( "shdr.sh_offset = %x\n", shdr.sh_offset );
            //my_printf( "shdr.sh_size = %x\n", shdr.sh_size );
            //my_printf( "shdr.sh_entsize = %x\n", shdr.sh_entsize );
            out_addr = base_addr + shdr.sh_addr;
            out_size = shdr.sh_size;
           // my_printf("out_addry = %lx, out_size = %lx\n", out_addr, out_size); 
           // my_printf("shdr.sh_addry = %lx, base_addr = %lx\n", shdr.sh_addr, base_addr); 
            for( i = 0; i < out_size; i += 8 ){
                 get_off = *(int32_t *)(out_addr+i);  
                 got_item = *(uint32_t *)(out_addr + i + 4);
			   uint32_t fun_offset,fun_addr;
                 //my_printf( "get_off = %x\n", get_off );
			   //my_printf( "got_item = %x\n", got_item );
			   //my_printf( "get_off1 = %x\n", shdr.sh_addr - (~get_off +1)&0xffff )+i;
			   //my_printf( "func point.0 = %x\n", shdr.sh_addr + i - ((~get_off +1)&0xfffffff) + base_addr );
                  
			   //my_printf( "func point.1 = %x\n", shdr.sh_addr + i - ((~get_off +1)&0xfffffff) + base_addr - base_addr );

			   fun_offset = shdr.sh_addr + i - ((~get_off +1)&0xfffffff);
			   fun_addr   = fun_offset + base_addr; 
                 my_printf( "fun_offset = %x\n", fun_offset );
			   my_printf( "fun_addr = %x\n", fun_addr );

			   if( fun_offset == 0xea4 ){
                     macdbg_dmphex(fun_addr, 100);
			   }
				 
			   //shdr.sh_addr + i 描述函数指针的虚拟地址的偏移位置的虚拟地址
			   //*(shdr.sh_addr + i)描述函数指针的虚拟地址的偏移位置
			   //(相对于描述函数指针的虚拟地址的虚拟地址) 为负数
			   //base_addr 该进程内核内存映射的基地址
                 //my_printf( "got_item = %x\n\n", got_item );
			   //my_printf( "got_item = %d\n", got_item );
            }
        }else{
            //my_printf( "name_idx1 = %x\n", name_idx );
           // my_printf( "string_table[name_idx]1 = %s\n", &string_table[name_idx] );
        }
    }

    free(string_table);
    close(fd);
    return 0;
}

#define DEVICE_COM    "/dev/ttyS0"


void init_ttyS(int fd)
{
	struct termios options;
	memset( &options, 0, sizeof(options) );
	cfsetispeed( &options, B115200 );
	cfsetospeed( &options, B115200 );
  	options.c_cflag |=(CS8|CLOCAL|CREAD);        
  	options.c_iflag &=IGNPAR;
    options.c_lflag &= ~ICANON; 		
	//raw Added by czj不等回车输入
    options.c_lflag &= ~ECHO;		
	//raw Added by czj不回显
	tcflush(fd,TCIFLUSH);
    tcsetattr(fd, TCSANOW, &options);
    //fcntl(fd, F_SETFL, 0);

}


int com_appstart(void)
{
	int fd;
	//fd = open( DEVICE_COM, O_RDWR|O_NOCTTY|O_NONBLOCK ); 

	fd = open( DEVICE_COM, O_RDWR |O_NOCTTY|O_NONBLOCK);
	if( fd == -1 ){	
		perror("open DEVICE_COM");
	}else{
		//init_ttyS( fd );	
	}

	//fcntl(fd,F_SETFL,0);
	return fd;
}



#define SAFE_SET_VALUE(t, v)   if(t) *(t) = (v)


static inline Elf32_Shdr *findSectionByName(struct ElfInfo *info, const char *sname){
	Elf32_Shdr *target = NULL;
	int i;
	Elf32_Shdr *shdr = info->shdr;
	for( i=0; i<info->ehdr->e_shnum; i++){
		const char *name = (const char *)(shdr[i].sh_name + info->shstr);
		if(!strncmp(name, sname, strlen(sname))){
			target = (Elf32_Shdr *)(shdr + i);
			break;
		}
	}

	return target;
}


static inline void getSectionInfo(struct ElfInfo *info, const char *name, Elf32_Word *pSize, Elf32_Shdr **ppShdr, void **data){
	Elf32_Shdr *_shdr = findSectionByName(info, name);

	if(_shdr){
		SAFE_SET_VALUE(pSize, _shdr->sh_size / _shdr->sh_entsize);
		//SAFE_SET_VALUE(data, reinterpret_cast<T>(info.elf_base + _shdr->sh_offset));

		SAFE_SET_VALUE(data, (info->elf_base + _shdr->sh_offset) );
          //if(data) *(data) = (123);
		
	}else{
		LOGE("[-] Could not found section %s\n", name);
		exit(-1);
	}

	SAFE_SET_VALUE(ppShdr, _shdr);
}



static inline Elf32_Phdr *findSegmentByType(struct ElfInfo *info, const Elf32_Word type){
	Elf32_Phdr *target = NULL;
	Elf32_Phdr *phdr = info->phdr;
     int i;
	for( i=0; i<info->ehdr->e_phnum; i++){
		if(phdr[i].p_type == type){
			target = phdr + i;
			break;
		}
	}

	return target;
}



static void getSegmentInfo( struct ElfInfo *info, const Elf32_Word type, Elf32_Phdr **ppPhdr,
	Elf32_Word *pSize, Elf32_Dyn **data){
	Elf32_Phdr *_phdr = findSegmentByType(info, type);

	if(_phdr){

		if(info->handle->fromfile){ //文件读取
			//SAFE_SET_VALUE(data, reinterpret_cast<T>(info.elf_base + _phdr->p_offset));
              SAFE_SET_VALUE(data, (info->elf_base + _phdr->p_offset));
			
			SAFE_SET_VALUE(pSize, _phdr->p_filesz);
		}else{ //从内存读取
			//SAFE_SET_VALUE(data, reinterpret_cast<T>(info.elf_base + _phdr->p_vaddr));

			SAFE_SET_VALUE(data, (info->elf_base + _phdr->p_vaddr) );
			SAFE_SET_VALUE(pSize, _phdr->p_memsz);
		}

	}else{
		LOGE("[-] Could not found segment type is %d\n", type);
		exit(-1);
	}

	SAFE_SET_VALUE(ppPhdr, _phdr);
}





void getElfInfoBySectionView(struct ElfInfo *info, const ElfHandle *handle){

	info->handle = handle;
	info->elf_base = (uint8_t *) handle->base;
	info->ehdr = (Elf32_Ehdr *)(info->elf_base);
	info->shdr = (Elf32_Shdr *)(info->elf_base + info->ehdr->e_shoff);
	info->phdr = (Elf32_Phdr *)(info->elf_base + info->ehdr->e_phoff);

	Elf32_Shdr *shstr = (Elf32_Shdr *)(info->shdr + info->ehdr->e_shstrndx);
	info->shstr = (char *)(info->elf_base + shstr->sh_offset);

	getSectionInfo(info, ".dynstr", NULL, NULL, &info->symstr);
	getSectionInfo(info, ".dynamic", &info->dynsz, NULL, &info->dyn);
	getSectionInfo(info, ".dynsym", &info->symsz, NULL, &info->sym);
	getSectionInfo(info, ".rel.dyn", &info->reldynsz, NULL, &info->reldyn);
	getSectionInfo(info, ".rel.plt", &info->relpltsz, NULL, &info->relplt);

	Elf32_Shdr *hash = findSectionByName(info, ".hash");
	if(hash){
		uint32_t *rawdata = (uint32_t *)(info->elf_base + hash->sh_offset);
		info->nbucket = rawdata[0];
		info->nchain = rawdata[1];
		info->bucket = rawdata + 2;
		info->chain = info->bucket + info->nbucket;
	}
}








void getElfInfoBySegmentView( struct ElfInfo *info, const ElfHandle *handle )
{        
    int i = 0;                 
    info->handle = handle;                         
    info->elf_base = (uint8_t *)handle->base;         
    //LOGE( "info->handle = %x.\n", info->handle );
    //LOGE( "info->elf_base = %x.\n", info->elf_base );
    info->ehdr = (Elf32_Ehdr *)info->elf_base;
    //LOGE( "info->ehdr = %x.\n", info->ehdr );
     //macdbg_dmphex(info->ehdr, 0x100);
	//may be wrong

	//LOGE( "info->ehdr->e_shoff = %x.\n", info->ehdr->e_shoff );
	info->shdr = (Elf32_Shdr *)(info->elf_base + info->ehdr->e_shoff);
	//LOGE( "info->shdr = %x.\n", info->shdr );

	
	info->phdr = (Elf32_Phdr *)(info->elf_base + info->ehdr->e_phoff);
	//LOGE( "info->phdr = %x.\n", info->phdr );

	//info.shdr = reinterpret_cast<Elf32_Shdr *>(info.elf_base + info.ehdr->e_shoff);
	//info.phdr = reinterpret_cast<Elf32_Phdr *>(info.elf_base + info.ehdr->e_phoff);

	

	info->shstr = NULL;

	Elf32_Phdr *dynamic = NULL;
	Elf32_Word size = 0;

	uint32_t *rawdata = NULL;

	getSegmentInfo(info, PT_DYNAMIC, &dynamic, &size, &info->dyn);
	if(!dynamic){
		LOGE("[-] could't find PT_DYNAMIC segment");
		exit(-1);
	}
	info->dynsz = size / sizeof(Elf32_Dyn);

	Elf32_Dyn *dyn = info->dyn;
	for(i=0; i<info->dynsz; i++, dyn++){

		switch(dyn->d_tag){

		case DT_SYMTAB:
			info->sym = (Elf32_Sym *)(info->elf_base + dyn->d_un.d_ptr);
			break;

		case DT_STRTAB:
			info->symstr = (const char *)(info->elf_base + dyn->d_un.d_ptr);
			break;

		case DT_REL:
			info->reldyn = (Elf32_Rel *)(info->elf_base + dyn->d_un.d_ptr);
			break;

		case DT_RELSZ:
			info->reldynsz = dyn->d_un.d_val / sizeof(Elf32_Rel);
			break;

		case DT_JMPREL:
			info->relplt = (Elf32_Rel *)(info->elf_base + dyn->d_un.d_ptr);
			break;

		case DT_PLTRELSZ:
			info->relpltsz = dyn->d_un.d_val / sizeof(Elf32_Rel);
			break;

		case DT_HASH:
			rawdata = (uint32_t *)(info->elf_base + dyn->d_un.d_ptr);
			info->nbucket = rawdata[0];
			info->nchain = rawdata[1];
			info->bucket = rawdata + 2;
			info->chain = info->bucket + info->nbucket;
			info->symsz = info->nchain;
			break;
		}
	}

}



unsigned elf_hash(const char *name) 
{
	const unsigned char *tmp = (const unsigned char *) name;
	unsigned h = 0, g;

	while (*tmp) {
		h = (h << 4) + *tmp++;
		g = h & 0xf0000000;
		h ^= g;
		h ^= g >> 24;
	}
	return h;
}



void findSymByName(struct ElfInfo *info, const char *symbol, Elf32_Sym **sym, int *symidx) {
	Elf32_Sym *target = NULL;

	unsigned hash = elf_hash(symbol);
	uint32_t index = info->bucket[hash % info->nbucket];

	if (!strcmp(info->symstr + info->sym[index].st_name, symbol)) {
		target = info->sym + index;
	}

	if (!target) {
		do {
			index = info->chain[index];
			if (!strcmp(info->symstr + info->sym[index].st_name, symbol)) {
				target = info->sym + index;
				break;
			}

		} while (index != 0);
	}

	if(target){
		SAFE_SET_VALUE(sym, target);
		SAFE_SET_VALUE(symidx, index);
	}
}





#define PAGE_START(addr) (~(getpagesize() - 1) & (addr))

static int modifyMemAccess(void *addr, int prots){
	void *page_start_addr = (void *)PAGE_START((uint32_t)addr);
	return mprotect(page_start_addr, getpagesize(), prots);
}

static int clearCache(void *addr, size_t len){
	void *end = (uint8_t *)addr + len;
	syscall(0xf0002, addr, end);
     return 0;
}

static int replaceFunc(void *addr, void *replace_func, void **old_func){
	int res = 0;


	return 0;
	if(*(void **)addr == replace_func){
		LOGE("addr %p had been replace.\n", addr);
		goto fails;
	}
	

	if(!*old_func){
		*old_func = *(void **)addr;
	}
	



	if(modifyMemAccess((void *)addr, PROT_EXEC|PROT_READ|PROT_WRITE)){
		LOGE("[-] modifymemAccess fails, error %s.", strerror(errno));
		res = 1;
		goto fails;
	}

	


	//LOGI("[+]addr is %p, old_func is %p, replace_func is %p, new_func %p.\n",
	//		addr, *old_func, replace_func, *(uint32_t *)addr);

	

	*(void **)addr = replace_func;
	
	clearCache(addr, getpagesize());
	//LOGI("[+]addr is %p, old_func is %p, replace_func is %p, new_func %p.\n",
	//	addr, *old_func, replace_func, *(uint32_t *)addr);
    
	fails:
	return res;
}

//#define R_ARM_ABS32 0x02
//#define R_ARM_GLOB_DAT 0x15
//#define R_ARM_JUMP_SLOT 0x16

int elfHook( const char *soname, const char *symbol, void *replace_func, void **old_func )
{
    //assert(old_func);
    //assert(replace_func);
    //assert(symbol);
                  
    int i;
    ElfHandle* handle = openElfBySoname(soname);
    struct ElfInfo info;
    Elf32_Rel rel;
    getElfInfoBySegmentView( &info, handle );           
    Elf32_Sym *sym = NULL;
    int symidx = 0;
    LOGI( "handle->base = %p.\n", handle->base );
    my_printf( "ioctl = %p\n", ioctl );
    //printfRelInfo(&info);
    //printfSymbols(&info);
    //printfDynamics(&info);
    //printSegments(&info);
    //printSections(&info);                                               
    macdbg_dmphex( handle->base+0x3f00, 0x140 );	
    findSymByName( &info, symbol, &sym, &symidx );
    if( !sym ){                     
        LOGE( "[-] Could not find symbol %s\n", symbol );
        goto fails;
    }else{
        LOGI( "[+] sym %p, symidx %d.\n", sym, symidx );
    }
                  
	for (i = 0; i < info.relpltsz; i++) {
		rel = info.relplt[i];
		if (ELF32_R_SYM(rel.r_info) == symidx && ELF32_R_TYPE(rel.r_info) == R_ARM_JUMP_SLOT) {
             

			LOGI("rel.r_offset = %x.\n", rel.r_offset);
			void *addr = (void *) (info.elf_base + rel.r_offset);
			
			if (replaceFunc(addr, replace_func, old_func)){
				LOGI("op 4123.\n"); 
				goto fails;
			}
              
			//only once
			break;
		}
	}

	for (i = 0; i < info.reldynsz; i++) {
		
		rel = info.reldyn[i];
		LOGI( "rel.r_info = %x.\n", rel.r_info );
		if (ELF32_R_SYM(rel.r_info) == symidx &&
				(ELF32_R_TYPE(rel.r_info) == R_ARM_ABS32
						|| ELF32_R_TYPE(rel.r_info) == R_ARM_GLOB_DAT)) {


			void *addr = (void *) (info.elf_base + rel.r_offset);
			if (replaceFunc(addr, replace_func, old_func))
				goto fails;
		}
	}

	fails:
	closeElfBySoname(handle);
	return 0;
}




int hook_entry1(char * a)
{
    
    //
	 g_com_fd = com_appstart();
	 my_printf( "g_com_fd = %d\n", g_com_fd );
	 my_printf( "in hook_entry2, param is %s\n", a );
	 //hook_eglSwapBuffers(); 
      //write(g_com_fd,"stdout\n",7);


	  
	  ElfHandle* handle = openElfBySoname(LIBSF_PATH);
		  struct ElfInfo info;
	  
		  getElfInfoBySegmentView(&info, handle);
	  
		  Elf32_Sym *sym = NULL;
		  int symidx = 0;
	  
		  //findSymByName(&info, "strlen", &sym, &symidx);

		  findSymByName(&info, "test_fun0", &sym, &symidx);
	  
		  if(!sym){
			  LOGE("[-] Could not find symbol %s", "strlen");
			  goto fails;
		  }else{
			  LOGI("[+] sym %p, symidx %d.", sym, symidx);
		  }



       fails:
     my_printf( "mypid = %d\n", getpid() );
        my_printf("gogogogogogo234!\n");  
       
       close(g_com_fd);
	
    
	
    return 0;
}


typedef int (*strlen_fun)(const char *);
strlen_fun old_strlen = NULL;
                                    
                                     
                                 
int test_funk1( int a )            
{                                         
    a = a*2;                             
    return printf( " a = %d\n", a );                
}                                               
                                            
                                          
int test_funk0(int a)
{
   a=a*2;
   a= test_funk1(a);
   return a;
}


typedef void * (* func_pointer)(void *arg);

int inject_do_create_thread(func_pointer thread_func, void *arg )
{   
    int ret,status;
    int first_run;
    int  c,j;
    pthread_t tmp_thread_id;	
    int Threaderr;
    char log[200]; 
    int connect_number = 6;
    int fdListen = -1, new_fd = -1;	
    //struct sockaddr_un peeraddr;
    //socklen_t socklen = sizeof (peeraddr);
    int numbytes ;
    char buff[256];	
    pthread_attr_t attr;              
    pthread_t socket_java_thread_id;
    pthread_attr_init (&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    Threaderr = pthread_create( &tmp_thread_id, NULL, thread_func, arg );
    ret = pthread_detach(tmp_thread_id);
    if( Threaderr != 0 ){
        //debug_msg("pthread_create error.\n");
    }
    return tmp_thread_id;
}


void *test_fuck_0(void *arg)
{      
    while(1){
      
      ioctl(1,2,3);
      //my_printf( "*arg = 0x%x\n", *(int *)arg );
      //my_printf( "ioctl = 0x%p\n", ioctl );
	  //sleep(1);
    }
    
}




void create_test_thread()
{    
    int arg = 0x03;
    func_pointer test_func = NULL;          
    test_func = test_fuck_0;
    inject_do_create_thread( test_func, (void *)&arg );

	
}


				




unsigned char test_g_array[20] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, };
size_t my_strlen123(int a, int b, int c)
{      
    //LOGI("strlen was called 1111111111111111111111.\n");
    //int len = old_strlen(str);
    //return len * 4;
    //LOGI("in my_strlen.\n");
    //LOGI( "a = %x\n", a ); 
    //LOGI( "b = %x\n", b ); 
    //LOGI( "c = %x\n", c ); 
    
    int out_bl,result;	

	create_test_thread();
    #if 0
    	asm volatile(
                "nop\n" \
                "mov r1, %0\n" 
                :"=m"(out_bl): "r" (test_g_array) : "r0", "r1", "r2", "r3" );
    #endif


    #if 1
    //此处可以测试任何汇编指令
	asm volatile(
	               "nop  \n" 
	               "mov r2, %2 \n" 
                    "ldr %0, [r2, #4]! \n"
                    "mov %1, r2 \n"
	:"=r"(result), "=r"(out_bl):"r"(&test_g_array[0]): "r0", "r1", "r2", "r3" );
    //=-->输出变量 r寄存器           输入变量 r寄存器   破坏的寄存器
    #endif 			
    //my_printf( "bianlian = 0x%x\n", result );
	//my_printf( "bianlian = 0x%x\n", result );
	//my_printf( "out_bl = 0x%x\n", out_bl );
    //macdbg_dmphex(test_g_array, 100);
    return 2;
}



size_t my_ioctl123(void)
{      
    
	//my_printf( "in my_ioctrl123.\n" );
	
    return 2;
}


//strlen_fun global_strlen1 = (strlen_fun)strlen;
//strlen_fun global_strlen2 = (strlen_fun)strlen;

#define SHOW(x) LOGI("%s is %d\n", #x, x)

//extern "C" jint Java_com_example_allhookinone_HookUtils_elfhook(JNIEnv *env, jobject thiz){



int test1(int a)
{                
    int _src;
    _src =1;
    asm volatile(
                "nop\n" \
                "mov r0, %0\n" \
                "ADR R12, 0xD4C\n" \
                "mov r0, %0\n" \
                : : "r" (_src) : "r0", "r1", "r2", "r3" );
             //:输出:输入:破坏的寄存器
             //"r" 告诉编译器使用寄存器处理输入变量

			 //asm volatile("mcr p15, 0, %0, c14, c2, 0" : : "r" (val));

//			  ADR             R12, 0xD4C
//.plt:00000D48                 ADD             R12, R12, #0x3000
//.plt:00000D4C                 LDR             PC, [R12,#(ioctl_ptr - 0x3D4C)]! ; __imp_ioctl


//	ioctl(1,2,3);

			 
    return _src;
}




int test_strlen(void)
{
   int ret;

   char buf[12]={'0', '1','2','\0'};
   LOGI( "strlen = %p\n", strlen );
	LOGI( "&strlen = %p\n", &strlen ); 
	ret=strlen("123");
	ret=strlen(buf);
	 LOGI( "strlen = %d\n", ret );

	 LOGI( "strlenqwe = %x\n", test1(2) );

	 ioctl(1,2,3);
    return ret;
}


int hook_entry(char * a)
{    
    const char *str = "hello world";
    g_com_fd = com_appstart();
    //my_printf( "g_com_fd = %d\n", g_com_fd );
    //my_printf( "in hook_entry2, param is %s\n", a );
	 
    strlen_fun local_strlen1 = (strlen_fun)strlen;
    //strlen_fun local_strlen2 = (strlen_fun)strlen;
    //int len0 = global_strlen1(str);
    //int len1 = global_strlen2(str);
    int len2 = local_strlen1(str);
    //int len3 = local_strlen2(str);
    //int len4 = strlen(str);
    //int len5 = strlen(str);
    //LOGI( "global_strlen1 = %p\n", global_strlen1 );
    //LOGI( "&global_strlen1 = %p\n", &global_strlen1 );
    //LOGI( "global_strlen2 = %p\n", global_strlen2 );


	
	 



    //LOGI( "local_strlen1 = %p\n", local_strlen1 );
	//LOGI( "&local_strlen1 = %p\n", &local_strlen1 );
    //LOGI( "local_strlen2 = %p\n", local_strlen2 );
    //LOGI( "strlen = %p\n", strlen );
    //LOGI("hook before:\n");
	//test_strlen();
    //SHOW(len0);
    //SHOW(len1);
    //SHOW(len2);
    //SHOW(len3);
    //SHOW(len4);
    //SHOW(len5);
    //elfHook("libonehook.so", "strlen", (void *)my_strlen, (void **)&old_strlen);
                           
    //elfHook(LIBSF_PATH, "strlen", (void *)my_strlen, (void **)&old_strlen);

	//elfHook(LIBSF_PATH, "strlen", (void *)my_strlen, (void **)&old_strlen);


     LOGI( "my_ioctl123 = %p\n", my_ioctl123 );

    my_strlen123(1,2,3);
    elfHook( LIBSF_PATH2, "ioctl", (void *)my_ioctl123, (void **)&old_strlen );           
    LOGI("hook after.\n");
        
                  	
	//:00003FF8 ioctl_ptr 

	//test_strlen();
      
	//sleep(5);
          	
    //LOGI( "global_strlen1 = %p\n", global_strlen1 );
    //LOGI( "global_strlen2 = %p\n", global_strlen2 );
    //LOGI( "local_strlen1 = %p\n", local_strlen1 );
    //LOGI( "local_strlen2 = %p\n", local_strlen2 );
    //LOGI( "strlen = %p\n", strlen );      
    //len0 = global_strlen1(str);
    //len1 = global_strlen2(str);
    //len2 = local_strlen1(str);
    //len3 = local_strlen2(str);
    //len4 = strlen(str);
    //len5 = strlen(str);
    //LOGI("hook after:\n");
    //SHOW(len0);
    //SHOW(len1);
    //SHOW(len2);
    //SHOW(len3);
    //SHOW(len4);
    //SHOW(len5);
    close(g_com_fd);
    return 0;
}








